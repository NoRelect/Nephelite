using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Nephelite.Services;

public class KeyService
{
    private readonly JsonWebKey _privateKey;
    private readonly JsonWebKey _publicKey;
    
    public KeyService()
    {
        var key = RSA.Create(4096);
        var privateRsaKey = new RsaSecurityKey(key);
        privateRsaKey.KeyId = Convert.ToBase64String(privateRsaKey.ComputeJwkThumbprint());
        _privateKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(privateRsaKey);
        _publicKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(key.ExportParameters(false))
        {
            KeyId = _privateKey.KeyId
        });
    }

    public JsonWebKeySet GetPublicJsonWebKeySet()
    {
        var keys = new JsonWebKeySet();
        keys.Keys.Add(_publicKey);
        return keys;
    }
}