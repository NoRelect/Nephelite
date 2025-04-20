namespace Nephelite.Services;

public class KeyService
{
    private const string KeyMaterialCacheName = "keyMaterial";
    private const string SigningKeyField = "signingKey";
    private const string RegisterSessionEncryptionKeyField = "registerSessionEncryptionKey";
    private const string AuthenticateSessionEncryptionKeyField = "authenticateSessionEncryptionKey";
    private const string AccessTokenEncryptionKeyField = "accessTokenEncryptionKey";
    private const string AuthorizationCodeEncryptionKeyField = "authorizationCodeEncryptionKey";

    private readonly KubernetesService _kubernetesService;
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<KeyService> _logger;

    public KeyService(
        KubernetesService kubernetesService,
        IMemoryCache memoryCache,
        ILogger<KeyService> logger)
    {
        _kubernetesService = kubernetesService;
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public async Task<KeyMaterial> GetKeyMaterial(CancellationToken cancellationToken)
    {
        if (_memoryCache.TryGetValue<KeyMaterial>(KeyMaterialCacheName, out var existingKeyMaterial))
            return existingKeyMaterial!;

        IDictionary<string, byte[]>? secret = null;
        try
        {
            secret = await _kubernetesService.GetSecret(cancellationToken);
        }
        catch (HttpOperationException)
        {
        }
        while (secret == null && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                await _kubernetesService.CreateImmutableSecret(new Dictionary<string, byte[]>
                {
                    { SigningKeyField, RSA.Create(4096).ExportRSAPrivateKey() },
                    { RegisterSessionEncryptionKeyField, RandomNumberGenerator.GetBytes(32) },
                    { AuthenticateSessionEncryptionKeyField, RandomNumberGenerator.GetBytes(32) },
                    { AccessTokenEncryptionKeyField, RandomNumberGenerator.GetBytes(32) },
                    { AuthorizationCodeEncryptionKeyField, RandomNumberGenerator.GetBytes(32) },
                }, cancellationToken);
            }
            catch (HttpOperationException ex)
            {
                _logger.LogWarning("Exception while creating the key material {Exception}", ex);
            }
            try
            {
                secret = await _kubernetesService.GetSecret(cancellationToken);
            }
            catch (HttpOperationException ex)
            {
                _logger.LogWarning("Exception while fetching the key material {Exception}", ex);
            }
        }
        if (secret == null)
            throw new TaskCanceledException();

        var signingKey = RSA.Create();
        signingKey.ImportRSAPrivateKey(secret[SigningKeyField], out _);
        var publicSigningKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new RsaSecurityKey(signingKey.ExportParameters(false)));

        var keyMaterial = new KeyMaterial
        {
            SigningKey = new SigningCredentials(
                new RsaSecurityKey(signingKey),
                SecurityAlgorithms.RsaSha256),
            SigningPublicKey = publicSigningKey,
            RegisterSessionEncryptionKey = new ChaCha20Poly1305(secret[RegisterSessionEncryptionKeyField]),
            AuthenticateSessionEncryptionKey = new ChaCha20Poly1305(secret[AuthenticateSessionEncryptionKeyField]),
            AccessTokenEncryptionKey = new EncryptingCredentials(
                new SymmetricSecurityKey(secret[AccessTokenEncryptionKeyField]),
                SecurityAlgorithms.Aes256KW,
                SecurityAlgorithms.Aes256CbcHmacSha512),
            AuthorizationCodeEncryptionKey = new EncryptingCredentials(
                new SymmetricSecurityKey(secret[AuthorizationCodeEncryptionKeyField]),
                SecurityAlgorithms.Aes256KW,
                SecurityAlgorithms.Aes256CbcHmacSha512),
        };

        _memoryCache.Set(KeyMaterialCacheName, keyMaterial, TimeSpan.FromMinutes(1));
        return keyMaterial;
    }

    public static string Encrypt(ChaCha20Poly1305 key, string data)
    {
        var plain = Encoding.UTF8.GetBytes(data);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        key.Encrypt(nonce, plain, cipher, tag);
        return Convert.ToBase64String(nonce) + "." + Convert.ToBase64String(cipher) + "." + Convert.ToBase64String(tag);
    }

    public static string Decrypt(ChaCha20Poly1305 key, string data)
    {
        var parts = data.Split(".").Select(Convert.FromBase64String).ToArray();
        var nonce = parts[0];
        var cipher = parts[1];
        var tag = parts[2];
        var plain = new byte[cipher.Length];
        key.Decrypt(nonce, cipher, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }
}