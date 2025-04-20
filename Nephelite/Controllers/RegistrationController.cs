namespace Nephelite.Controllers;

[ApiController]
[Route("/")]
public class RegistrationController(
    KubernetesService kubernetesService,
    KeyService keyService,
    IFido2 fido2,
    ILogger<RegistrationController> logger) : ControllerBase
{

    [HttpGet]
    [Route("registrationOptions")]
    public async Task<IActionResult> GetRegisterOptions([FromQuery] string username, CancellationToken cancellationToken)
    {
        var credentialCreateOptions = fido2.RequestNewCredential(new Fido2User
            {
                Id = Encoding.UTF8.GetBytes(username),
                Name = username,
                DisplayName = username
            },
            new List<PublicKeyCredentialDescriptor>(),
            new AuthenticatorSelection
            {
                UserVerification = UserVerificationRequirement.Required,
                RequireResidentKey = true
            }, AttestationConveyancePreference.None);
        var keyMaterial = await keyService.GetKeyMaterial(cancellationToken);
        var sessionInfo = new RegistrationSessionInformation
        {
            CreateOptions = credentialCreateOptions
        };
        return new JsonResult(new
        {
            Session = KeyService.Encrypt(keyMaterial.RegisterSessionEncryptionKey,
                JsonSerializer.Serialize(sessionInfo)),
            Options = credentialCreateOptions
        });
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> RegisterCredential(
        [FromForm] string session,
        [FromForm] string response,
        CancellationToken cancellationToken)
    {
        var keyMaterial = await keyService.GetKeyMaterial(cancellationToken);
        var sessionInfo = JsonSerializer.Deserialize<RegistrationSessionInformation>(
            KeyService.Decrypt(keyMaterial.RegisterSessionEncryptionKey, session));
        var attestationResponse = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(response);

        if (sessionInfo == null || attestationResponse == null)
        {
            HttpContext.Response.StatusCode = 400;
            logger.LogWarning("Invalid session information or attestation response");
            return new EmptyResult();
        }

        try
        {
            var result = await fido2.MakeNewCredentialAsync(attestationResponse, sessionInfo.CreateOptions,
                CheckIfCredentialIsUniqueToUser, cancellationToken: cancellationToken);
            if (result.Result == null)
            {
                HttpContext.Response.StatusCode = 400;
                logger.LogWarning("Empty credential result: {Result}", result);
                return new EmptyResult();
            }

            var escapedUsername = result.Result.User.Name.Replace("\"", "\\\"");
            var content = $"""
                          apiVersion: nephelite.norelect.ch/v1
                          kind: User
                          metadata:
                            name: "{escapedUsername}"
                          spec:
                            username: "{escapedUsername}"
                            email: "{escapedUsername}@example.com"
                            groups:
                              - "users"
                            credentials:
                              - credentialId: "{Convert.ToBase64String(result.Result.CredentialId)}"
                                publicKey: "{Convert.ToBase64String(result.Result.PublicKey)}"
                          """;
            return new FileContentResult(Encoding.UTF8.GetBytes(content), "application/yaml");
        }
        catch (Exception ex)
        {
            HttpContext.Response.StatusCode = 400;
            logger.LogWarning("Invalid attestationResponse: {Exception}", ex);
            return new EmptyResult();
        }
    }

    private async Task<bool> CheckIfCredentialIsUniqueToUser(IsCredentialIdUniqueToUserParams args,
        CancellationToken cancellationToken)
    {
        var users = await kubernetesService.GetUsers(cancellationToken);
        var user = users.FirstOrDefault(u => u.Spec.Username == args.User.Name);
        return user == null || user.Spec.Credentials.All(c => !c.CredentialId.SequenceEqual(args.CredentialId));
    }
}