namespace Nephelite.Model;

public class TokenRequest
{
    [FromQuery(Name = "grant_type")]
    public string? GrantType { get; set; }
    
    [FromQuery(Name = "code")]
    public string? Code { get; set; }
    
    [FromQuery(Name = "redirect_uri")]
    public string? RedirectUri { get; set; }
}