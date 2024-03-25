namespace Nephelite.Model.OpenId;

public class AuthorizationRequest
{
    [FromQuery(Name = "scope")]
    public string? Scope { get; set; }
    
    [FromQuery(Name = "response_type")]
    public string? ResponseType { get; set; }
    
    [FromQuery(Name = "client_id")]
    public string? ClientId { get; set; }
    
    [FromQuery(Name = "redirect_uri")]
    public string? RedirectUri { get; set; }
    
    [FromQuery(Name = "state")]
    public string? State { get; set; }
    
    [FromQuery(Name = "response_mode")]
    public string? ResponseMode { get; set; }
    
    [FromQuery(Name = "nonce")]
    public string? Nonce { get; set; }
    
    [FromQuery(Name = "prompt")]
    public string? Prompt { get; set; }
}