using System.Text.Json.Serialization;

namespace Nephelite.Model;

public class OpenIdProviderMetadata
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = default!;
    
    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; set; } = default!;
    
    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; set; } = default!;
    
    [JsonPropertyName("userinfo_endpoint")]
    public string UserInfoEndpoint { get; set; } = default!;
    
    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; set; } = default!;

    [JsonPropertyName("scopes_supported")]
    public List<string> SupportedScopes { get; set; } = new();
    
    [JsonPropertyName("response_types_supported")]
    public List<string> SupportedResponseTypes { get; set; } = new();
        
    [JsonPropertyName("subject_types_supported")]
    public List<string> SupportedSubjectTypes { get; set; } = new();
        
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public List<string> SupportedIdTokenSigningAlgorithmValues { get; set; } = new();
}