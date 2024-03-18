namespace Nephelite.CustomResources;

public class V1User : CustomResource<V1UserSpec>
{
    
}

public class V1UserSpec
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = default!;
    
    [JsonPropertyName("email")]
    public string Email { get; set; } = default!;

    [JsonPropertyName("credentials")]
    public List<V1UserCredential> Credentials { get; set; } = new();
    
    [JsonPropertyName("groups")]
    public List<string> Groups { get; set; } = new();
}

public class V1UserCredential
{
    [JsonPropertyName("credentialId")]
    public byte[] CredentialId { get; set; } = default!;
    
    [JsonPropertyName("publicKey")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] PublicKey { get; set; } = default!;
}