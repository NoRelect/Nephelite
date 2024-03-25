namespace Nephelite.Controllers;

[ApiController]
[Route("/authorize")]
public class AuthorizationController : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly KubernetesService _kubernetesService;
    private readonly KeyService _keyService;
    private readonly NepheliteConfiguration _nepheliteConfiguration;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IFido2 fido2,
        KubernetesService kubernetesService,
        KeyService keyService,
        IOptions<NepheliteConfiguration> nepheliteConfiguration,
        ILogger<AuthorizationController> logger)
    {
        _fido2 = fido2;
        _kubernetesService = kubernetesService;
        _keyService = keyService;
        _nepheliteConfiguration = nepheliteConfiguration.Value;
        _logger = logger;
    }
    
    [HttpGet]
    public async Task<IActionResult> PromptAuthentication(
        [FromQuery] AuthorizationRequest request,
        CancellationToken cancellationToken)
    {
        var clients = await _kubernetesService.GetClients(cancellationToken);
        var client = clients.FirstOrDefault(c => c.ClientId == request.ClientId);
        if (client == null)
        {
            _logger.LogWarning("Request used an invalid client id: '{ClientId}'", request.ClientId);
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid client id"});
        }
        
        if (string.IsNullOrEmpty(request.RedirectUri) ||
            !client.RedirectUris.Contains(request.RedirectUri))
        {
            _logger.LogWarning("Request used an invalid redirect uri: '{RedirectUri}'", request.RedirectUri);
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid redirect uri"});
        }

        var scopes = request.Scope?.Split(" ") ?? Array.Empty<string>();
        if (!scopes.Contains("openid"))
        {
            _logger.LogWarning("Request is missing the openid scope: '{Scope}'", request.Scope);
            return RedirectWithError(request, "invalid_scope");
        }
        
        var validResponseTypes = new [] { "code", "id_token token", "id_token" };
        if (string.IsNullOrEmpty(request.ResponseType) || !validResponseTypes.Contains(request.ResponseType))
        {
            _logger.LogWarning("Request used an invalid response type: '{ResponseType}'", request.ResponseType);
            return RedirectWithError(request, "unsupported_response_type");
        }

        switch (request.ResponseType)
        {
            case "code" when !client.IsConfidentialClient:
                _logger.LogWarning("Request tried to use invalid response type for public client: {ResponseType}",
                    request.ResponseType);
                return RedirectWithError(request, "unauthorized_client");
            case "id_token token" or "id_token" when request.Nonce == null:
                _logger.LogWarning("Request tried to use implicit flow without nonce");
                return RedirectWithError(request, "invalid_request");
        }

        if (request.Prompt == "none")
        {
            // We do not keep track of who is logged in or not, so we always return the "not logged in" state
            return RedirectWithError(request, "login_required");
        }
        
        var assertionOptions = _fido2.GetAssertionOptions(
            new List<PublicKeyCredentialDescriptor>(),
            UserVerificationRequirement.Required,
            new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                UserVerificationMethod = true
            }
        );
        var keyMaterial = await _keyService.GetKeyMaterial(cancellationToken);

        var sessionInfo = new AuthorizationSessionInformation
        {
            AuthorizationRequest = request,
            AssertionOptions = assertionOptions,
            RequestStart = DateTime.UtcNow
        };
        var session = KeyService.Encrypt(keyMaterial.AuthenticateSessionEncryptionKey,
            JsonSerializer.Serialize(sessionInfo));
        var content = $"""
                       <!DOCTYPE html>
                       <html lang="en">
                           <head>
                               <title>Nephelite</title>
                               <link rel="stylesheet" href="css/style.css" />
                           </head>
                           <body>
                               <img class="logo" src="img/logo.png" alt="Nephelite Logo"> 
                               <script type="text/javascript" src="js/script.js"></script>
                               <script type="text/javascript">
                                   let session = "{session}";
                                   let options = {JsonSerializer.Serialize(assertionOptions)};
                                   authenticate(session, options);
                               </script>
                           </body>
                       </html>
                       """;
        return new FileContentResult(Encoding.UTF8.GetBytes(content), "text/html");
    }
    
    [HttpPost]
    public async Task<IActionResult> Authenticate(
        [FromForm] string session,
        [FromForm] string response,
        CancellationToken cancellationToken)
    {
        HttpContext.Response.Headers.CacheControl = "no-store";
        HttpContext.Response.Headers.Pragma = "no-cache";
        
        var clientResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(response);
        if (clientResponse == null)
        {
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid client response"});
        }

        var keyMaterial = await _keyService.GetKeyMaterial(cancellationToken);
        var decryptedSession = KeyService.Decrypt(keyMaterial.AuthenticateSessionEncryptionKey, session);
        var sessionInformation = JsonSerializer.Deserialize<AuthorizationSessionInformation>(decryptedSession);
        if (sessionInformation == null)
        {
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid session"});
        }

        var request = sessionInformation.AuthorizationRequest;

        var elapsedTime = DateTime.UtcNow.Subtract(sessionInformation.RequestStart);
        if (elapsedTime.TotalMinutes is < 0 or > 1)
        {
            _logger.LogWarning("Received request that has expired");
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Request expired"});
        }

        var users = await _kubernetesService.GetUsers(cancellationToken);
        var cred = users.SelectMany(u => u.Spec.Credentials)
                .FirstOrDefault(c => c.CredentialId.SequenceEqual(clientResponse.Id));

        if (cred == null)
        {
            _logger.LogWarning("Authentication tried with unknown credential: {CredentialId}", clientResponse.Id);
            return RedirectWithError(request, "access_denied");
        }

        var hexCredentialId = Convert.ToHexString(cred.CredentialId);
        var user = users.First(u => u.Spec.Credentials.Any(c => c == cred));
        var storedSignatureCounter = user.Status?.SignatureCounters
                .GetValueOrDefault(hexCredentialId, 0u) ?? 0u;

        AssertionVerificationResult result;
        try
        {
            result = await _fido2.MakeAssertionAsync(
                clientResponse,
                sessionInformation.AssertionOptions,
                cred.PublicKey,
                storedSignatureCounter,
                CheckCredentialBelongsToCorrectUser,
                cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Authentication failed: {Exception}", ex);
            return RedirectWithError(request, "access_denied");
        }

        var old = JsonSerializer.SerializeToDocument(user.Status);
        user.Status ??= new V1UserStatus();
        user.Status.SignatureCounters[hexCredentialId] = result.Counter;
        var patched = JsonSerializer.SerializeToDocument(user.Status);
        await _kubernetesService.PatchUser(user.Name(), old.CreatePatch(patched), cancellationToken);
        
        var commonClaims = new Dictionary<string, object?>
        {
            { "auth_time", (ulong)sessionInformation.RequestStart.Subtract(DateTime.UnixEpoch).TotalSeconds },
            { "sub", user.Spec.Username },
            { "email", user.Spec.Email },
            { "groups", user.Spec.Groups }
        };
        
        // Create OpenID spec compliant response with either
        // an authorization code, an id_token or an access token or a combination

        var jwtHandler = new JsonWebTokenHandler();
        var clients = await _kubernetesService.GetClients(cancellationToken);
        var client = clients.First(c => c.ClientId == sessionInformation.AuthorizationRequest.ClientId);
        var tokenLifetime = client.TokenLifetime ?? _nepheliteConfiguration.DefaultTokenLifetime;
        
        var expiryDate = sessionInformation.RequestStart.Add(tokenLifetime);
        var expiresIn = (int)expiryDate.Subtract(DateTime.UtcNow).TotalSeconds;
        var nonce = sessionInformation.AuthorizationRequest.Nonce;
        var idpUrl = $"https://{_nepheliteConfiguration.Host}";
        var accessTokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = idpUrl,
            Audience = idpUrl,
            IssuedAt = sessionInformation.RequestStart,
            Expires = expiryDate,
            Claims = commonClaims,
            SigningCredentials = keyMaterial.SigningKey,
            EncryptingCredentials = keyMaterial.AccessTokenEncryptionKey
        };
        if(!string.IsNullOrEmpty(nonce))
            accessTokenDescriptor.Claims.Add("nonce", nonce);
        var accessToken = jwtHandler.CreateToken(accessTokenDescriptor);
        
        var idTokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = idpUrl,
            Audience = request.ClientId,
            IssuedAt = sessionInformation.RequestStart,
            Expires = expiryDate,
            Claims = commonClaims,
            SigningCredentials = keyMaterial.SigningKey,
            EncryptingCredentials = null
        };
        
        if (request.ResponseType == "id_token token")
        {
            var hashBytes = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
            var atHash = WebEncoders.Base64UrlEncode(hashBytes[..(hashBytes.Length/2)]);
            idTokenDescriptor.Claims.Add("at_hash", atHash);
        }
        
        if (!string.IsNullOrEmpty(nonce))
        {
            idTokenDescriptor.Claims.Add("nonce", nonce);
        }

        var idToken = jwtHandler.CreateToken(idTokenDescriptor);

        var authorizationCode = jwtHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = idpUrl,
            Audience = idpUrl,
            IssuedAt = sessionInformation.RequestStart,
            Expires = expiryDate,
            Claims = new Dictionary<string, object>
            {
                { "access_token", accessToken },
                { "id_token", idToken },
                { "session_info", decryptedSession }
            },
            SigningCredentials = keyMaterial.SigningKey,
            EncryptingCredentials = keyMaterial.AuthorizationCodeEncryptionKey
        });
        
        var uriBuilder = new UriBuilder(new Uri(request.RedirectUri!));
        switch (request.ResponseType)
        {
            case "code":
                uriBuilder.Query = $"code={authorizationCode}&state={UrlEncoder.Default.Encode(request.State ?? "")}";
                return Redirect(uriBuilder.Uri.ToString());
            case "id_token token":
                uriBuilder.Fragment = $"access_token={UrlEncoder.Default.Encode(accessToken)}" +
                                      $"&token_type=Bearer"+
                                      $"&id_token={UrlEncoder.Default.Encode(idToken)}" +
                                      $"&state={UrlEncoder.Default.Encode(request.State ?? "")}" +
                                      $"&expires_in={expiresIn}" +
                                      $"&nonce={UrlEncoder.Default.Encode(request.Nonce ?? "")}";
                return Redirect(uriBuilder.Uri.ToString());
            case "id_token":
                uriBuilder.Fragment = $"id_token={UrlEncoder.Default.Encode(idToken)}" +
                                      $"&state={UrlEncoder.Default.Encode(request.State ?? "")}" +
                                      $"&expires_in={expiresIn}";
                return Redirect(uriBuilder.Uri.ToString());
            default:
                _logger.LogWarning("Invalid response type used: {ResponseType}", request.ResponseType);
                HttpContext.Response.StatusCode = 400;
                return new JsonResult(new { Error = "Invalid response type"});
        }
    }

    private async Task<bool> CheckCredentialBelongsToCorrectUser(IsUserHandleOwnerOfCredentialIdParams args,
        CancellationToken cancellationToken)
    {
        var users = await _kubernetesService.GetUsers(cancellationToken);
        var user = users.FirstOrDefault(u => Encoding.UTF8.GetBytes(u.Spec.Username).SequenceEqual(args.UserHandle));
        return user != null && user.Spec.Credentials.Any(c => c.CredentialId.SequenceEqual(args.CredentialId));
    }

    private RedirectResult RedirectWithError(AuthorizationRequest request, string error)
    {
        var uriBuilder = new UriBuilder(new Uri(request.RedirectUri!))
        {
            Query = $"error={error}&state={UrlEncoder.Default.Encode(request.State ?? "")}",
        };
        return Redirect(uriBuilder.Uri.ToString());
    }
}