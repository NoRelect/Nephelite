namespace Nephelite.Model.Internal;

public class KeyMaterial
{
    public JsonWebKey SigningPublicKey { get; set; } = default!;
    public SigningCredentials SigningKey { get; set; } = default!;
    public ChaCha20Poly1305 RegisterSessionEncryptionKey { get; set; } = default!;
    public ChaCha20Poly1305 AuthenticateSessionEncryptionKey { get; set; } = default!;
    public EncryptingCredentials AccessTokenEncryptionKey { get; set; } = default!;
    public EncryptingCredentials AuthorizationCodeEncryptionKey { get; set; } = default!;
}