namespace Nephelite.CustomResources;

public class V1PublicKeyCredential
{
    [JsonPropertyName("user")]
    public string User { get; set; } = default!;
    
    [JsonPropertyName("credentialId")]
    public byte[] CredentialId { get; set; } = default!;
    
    [JsonPropertyName("publicKey")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] PublicKey { get; set; } = default!;
}