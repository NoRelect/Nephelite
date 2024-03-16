namespace Nephelite.Model;

public class TokenRequest
{
    [FromForm(Name = "grant_type")]
    public string? GrantType { get; set; }
    
    [FromForm(Name = "code")]
    public string? Code { get; set; }
    
    [FromForm(Name = "redirect_uri")]
    public string? RedirectUri { get; set; }
    
    [FromForm(Name = "client_id")]
    public string? ClientId { get; set; }
    
    [FromForm(Name = "client_secret")]
    public string? ClientSecret { get; set; }
}