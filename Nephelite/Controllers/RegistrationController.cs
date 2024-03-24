namespace Nephelite.Controllers;

[ApiController]
[Route("/")]
public class RegistrationController : ControllerBase
{
    private readonly KubernetesService _kubernetesService;
    private readonly KeyService _keyService;
    private readonly NepheliteConfiguration _nepheliteConfiguration;
    private readonly IFido2 _fido2;
    private readonly ILogger<RegistrationController> _logger;

    public RegistrationController(
        KubernetesService kubernetesService,
        KeyService keyService,
        IOptions<NepheliteConfiguration> nepheliteConfiguration,
        IFido2 fido2,
        ILogger<RegistrationController> logger)
    {
        _kubernetesService = kubernetesService;
        _keyService = keyService;
        _nepheliteConfiguration = nepheliteConfiguration.Value;
        _fido2 = fido2;
        _logger = logger;
    }
    
    [HttpGet]
    [Route("registrationOptions")]
    public async Task<IActionResult> GetRegisterOptions([FromQuery] string username, CancellationToken cancellationToken)
    {
        var users = await _kubernetesService.GetUsers(cancellationToken);
        var user = users.FirstOrDefault(u => u.Username == username);
        var existingCredentials = user?.Credentials
            .Select(c => new PublicKeyCredentialDescriptor
            {
                Id = c.CredentialId,
                Type = PublicKeyCredentialType.PublicKey
            }).ToList() ?? new List<PublicKeyCredentialDescriptor>();
        var credentialCreateOptions = _fido2.RequestNewCredential(new Fido2User
            {
                Id = Encoding.UTF8.GetBytes(username),
                Name = username,
                DisplayName = username
            },
            existingCredentials,
            new AuthenticatorSelection
            {
                UserVerification = UserVerificationRequirement.Preferred,
                RequireResidentKey = true
            }, AttestationConveyancePreference.None);
        return new JsonResult(new
        {
            Session = _keyService.EncryptSession(JsonSerializer.Serialize(new RegistrationSessionInformation
            {
                CreateOptions = credentialCreateOptions
            })),
            Options = credentialCreateOptions
        });
    }
    
    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> RegisterCredential(
        [FromForm] string session,
        [FromForm] string response)
    {
        var sessionInfo = JsonSerializer.Deserialize<RegistrationSessionInformation>(
            _keyService.DecryptSession(session));
        var attestationResponse = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(response);

        if (sessionInfo == null || attestationResponse == null)
        {
            HttpContext.Response.StatusCode = 400;
            _logger.LogWarning("Invalid session information or attestation response");
            return new EmptyResult();
        }

        try
        {
            var result = await _fido2.MakeNewCredentialAsync(attestationResponse, sessionInfo.CreateOptions,
                CheckIfCredentialIsUniqueToUser);
            if (result.Result == null)
            {
                HttpContext.Response.StatusCode = 400;
                _logger.LogWarning("Empty credential result: {Result}", result);
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
            _logger.LogWarning("Invalid attestationResponse: {Exception}", ex);
            return new EmptyResult();
        }
    }

    private async Task<bool> CheckIfCredentialIsUniqueToUser(IsCredentialIdUniqueToUserParams args,
        CancellationToken cancellationToken)
    {
        var users = await _kubernetesService.GetUsers(cancellationToken);
        var user = users.FirstOrDefault(u => u.Username == args.User.Name);
        return user == null || user.Credentials.All(c => !c.CredentialId.SequenceEqual(args.CredentialId));
    }
}