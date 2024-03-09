using Microsoft.Extensions.Options;

namespace Nephelite.Controllers;

[ApiController]
[Route("/webauthn")]
public class WebAuthenticationController : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly IOptionsSnapshot<PublicKeyCredentialsConfiguration> _publicKeyCredentials;
    private readonly ILogger<WebAuthenticationController> _logger;

    public WebAuthenticationController(
        IFido2 fido2,
        IOptionsSnapshot<PublicKeyCredentialsConfiguration> publicKeyCredentials,
        ILogger<WebAuthenticationController> logger)
    {
        _fido2 = fido2;
        _publicKeyCredentials = publicKeyCredentials;
        _logger = logger;
    }
    
    [HttpGet]
    public async Task Get()
    {
        Response.Headers.ContentType = "text/html";
        const string content = """
                               <!DOCTYPE html>
                               <html>
                                   <head>
                                   </head>
                                   <body>
                                       <button onclick="createCredential()">Create credential</button>
                                       <button onclick="authenticate()">Authenticate</button>
                                       <script type="text/javascript" src="helpers.js"></script>
                                       <script type="text/javascript" src="webauthn.js"></script>
                                   </body>
                               </html>
                               """;
        await Response.Body.WriteAsync(Encoding.UTF8.GetBytes(content));
    }

    public class CredentialRequest
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = default!;
    }
    
    [HttpPost]
    [Route("registerOptions")]
    public JsonResult GetRegisterOptions(CredentialRequest credentialRequest)
    {
        var username = credentialRequest.Username;
        var user = new Fido2User
        {
            Id = Encoding.UTF8.GetBytes(username),
            Name = username,
            DisplayName = username,
        };
        var existingCredentials = _publicKeyCredentials.Value.Credentials
            .Select(c => new PublicKeyCredentialDescriptor
            {
                Id = c.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
            }).ToList();
        var credentialCreateOptions = _fido2.RequestNewCredential(user,
            existingCredentials,
            new AuthenticatorSelection
            {
                UserVerification = UserVerificationRequirement.Preferred,
                RequireResidentKey = false,
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform
            }, AttestationConveyancePreference.None);
        HttpContext.Session.SetString("fido2.attestationOptions", credentialCreateOptions.ToJson());
        return new JsonResult(credentialCreateOptions);
    }
    
    [HttpPost]
    [Route("register")]
    public async Task<JsonResult> RegisterCredential(AuthenticatorAttestationRawResponse attestationResponse)
    {
        var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
        HttpContext.Session.Remove("fido2.attestationOptions");
        var options = CredentialCreateOptions.FromJson(jsonOptions);

        var success = await _fido2.MakeNewCredentialAsync(attestationResponse, options, Callback);
        return new JsonResult(success);

        async Task<bool> Callback(IsCredentialIdUniqueToUserParams args, CancellationToken cancellation)
        {
            return await Task.FromResult(true);
        }
    }
    
    [HttpPost]
    [Route("authenticationOptions")]
    public JsonResult GetAuthenticationOptions()
    {
        var existingCredentials = _publicKeyCredentials.Value.Credentials
            .Select(c => new PublicKeyCredentialDescriptor
            {
                Id = c.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
            }).ToList();
        var options = _fido2.GetAssertionOptions(
            existingCredentials,
            UserVerificationRequirement.Preferred,
            new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                UserVerificationMethod = true
            }
        );

        HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());
        return new JsonResult(options);
    }
    
    [HttpPost]
    [Route("authenticate")]
    public async Task<JsonResult> Authenticate(AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {
        var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
        var options = AssertionOptions.FromJson(jsonOptions);
        var cred = _publicKeyCredentials.Value.Credentials
                .First(c => c.CredentialId.SequenceEqual(clientResponse.Id));

        var result = await _fido2.MakeAssertionAsync(
            clientResponse, options, cred.PublicKey, 0, Callback, cancellationToken: cancellationToken);

        return new JsonResult(result);

        async Task<bool> Callback(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellation)
        {
            return await Task.FromResult(true);
        }
    }
}