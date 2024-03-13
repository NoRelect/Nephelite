namespace Nephelite.Controllers;

[ApiController]
[Route("/authorize")]
public class AuthorizationController : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly IOptionsSnapshot<PublicKeyCredentialsConfiguration> _publicKeyCredentials;
    private readonly KeyService _keyService;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IFido2 fido2,
        IOptionsSnapshot<PublicKeyCredentialsConfiguration> publicKeyCredentials,
        KeyService keyService,
        ILogger<AuthorizationController> logger)
    {
        _fido2 = fido2;
        _publicKeyCredentials = publicKeyCredentials;
        _keyService = keyService;
        _logger = logger;
    }
    
    [HttpGet]
    public async Task Get()
    {
        var existingCredentials = _publicKeyCredentials.Value.Credentials
            .Select(c => new PublicKeyCredentialDescriptor
            {
                Id = c.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
            }).ToList();
        var assertionOptions = _fido2.GetAssertionOptions(
            existingCredentials,
            UserVerificationRequirement.Preferred,
            new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                UserVerificationMethod = true
            }
        );

        var state = _keyService.Encrypt(assertionOptions.ToJson());
        Response.Headers.ContentType = "text/html";
        var content = $$"""
                       <!DOCTYPE html>
                       <html>
                           <head>
                           </head>
                           <body>
                               <script type="text/javascript" src="helpers.js"></script>
                               <script type="text/javascript">
                                   let state = "{{state}}";
                                   let options = {{JsonSerializer.Serialize(assertionOptions)}};
                                   options.challenge = coerceToArrayBuffer(options.challenge);
                                   options.allowCredentials = options.allowCredentials.map((c) => {
                                       c.id = coerceToArrayBuffer(c.id);
                                       return c;
                                   });
                                   navigator.credentials.get({ publicKey: options }).then(credential => {
                                       let authData = new Uint8Array(credential.response.authenticatorData);
                                       let clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
                                       let rawId = new Uint8Array(credential.rawId);
                                       let sig = new Uint8Array(credential.response.signature);
                                       const data = {
                                           state: state,
                                           client_response: {
                                               id: credential.id,
                                               rawId: coerceToBase64Url(rawId),
                                               type: credential.type,
                                               extensions: credential.getClientExtensionResults(),
                                               response: {
                                                   authenticatorData: coerceToBase64Url(authData),
                                                   clientDataJSON: coerceToBase64Url(clientDataJSON),
                                                   signature: coerceToBase64Url(sig)
                                               }
                                           }
                                       };
                                       fetch("/authorize", {
                                          method: "POST",
                                          body: JSON.stringify(data),
                                          headers: {
                                              "Accept": "application/json",
                                              "Content-Type": "application/json"
                                          }
                                      })
                                   }).catch(e => {
                                       console.log(e);
                                       alert("Something went wrong: " + e);
                                   });
                               </script>
                           </body>
                       </html>
                       """;
        await Response.Body.WriteAsync(Encoding.UTF8.GetBytes(content));
    }

    public class AuthorizationPostRequest
    {
        [JsonPropertyName("state")]
        public string State { get; set; } = default!;
        
        [JsonPropertyName("client_response")]
        public AuthenticatorAssertionRawResponse ClientResponse { get; set; } = default!;
    }
    
    [HttpPost]
    public async Task<JsonResult> Authenticate(AuthorizationPostRequest request, CancellationToken cancellationToken)
    {
        var options = AssertionOptions.FromJson(_keyService.Decrypt(request.State));
        var cred = _publicKeyCredentials.Value.Credentials
                .First(c => c.CredentialId.SequenceEqual(request.ClientResponse.Id));

        var result = await _fido2.MakeAssertionAsync(
            request.ClientResponse, options, cred.PublicKey, 0, Callback, cancellationToken: cancellationToken);

        return new JsonResult(result);

        async Task<bool> Callback(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellation)
        {
            return await Task.FromResult(true);
        }
    }
}