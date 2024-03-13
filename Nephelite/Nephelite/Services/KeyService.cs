namespace Nephelite.Services;

public class KeyService
{
    private readonly RsaSecurityKey _privateKey;
    private readonly JsonWebKey _publicKey;
    private readonly ChaCha20Poly1305 _encryptionKey;
    
    public KeyService()
    {
        var key = RSA.Create(4096);
        _privateKey = new RsaSecurityKey(key);
        _privateKey.KeyId = Convert.ToBase64String(_privateKey.ComputeJwkThumbprint());
        _publicKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(key.ExportParameters(false))
        {
            KeyId = _privateKey.KeyId
        });

        var keyBytes = RandomNumberGenerator.GetBytes(32);
        _encryptionKey = new ChaCha20Poly1305(keyBytes);
    }

    public JsonWebKeySet GetPublicJsonWebKeySet()
    {
        var keys = new JsonWebKeySet();
        keys.Keys.Add(_publicKey);
        return keys;
    }

    public string Encrypt(string data)
    {
        var plain = Encoding.UTF8.GetBytes(data);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        _encryptionKey.Encrypt(nonce, plain, cipher, tag);
        return Convert.ToBase64String(nonce) + "." + Convert.ToBase64String(cipher) + "." + Convert.ToBase64String(tag);
    }

    public string Decrypt(string data)
    {
        var parts = data.Split(".").Select(Convert.FromBase64String).ToArray();
        var nonce = parts[0];
        var cipher = parts[1];
        var tag = parts[2];
        var plain = new byte[cipher.Length];
        _encryptionKey.Decrypt(nonce, cipher, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }
}