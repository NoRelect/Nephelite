namespace Nephelite.Controllers;

[ApiController]
[Route("/webauthn")]
public class WebAuthnController : ControllerBase
{
    private readonly IFido2 _fido2;

    public WebAuthnController(
        IFido2 fido2)
    {
        _fido2 = fido2;
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
        var credentialCreateOptions = _fido2.RequestNewCredential(user,
            new List<PublicKeyCredentialDescriptor>(),
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
}