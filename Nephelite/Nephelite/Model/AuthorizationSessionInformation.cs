namespace Nephelite.Model;

public class AuthorizationSessionInformation
{
    public AuthorizationRequest AuthorizationRequest { get; set; } = default!;
    
    public AssertionOptions AssertionOptions { get; set; } = default!;

    public DateTime RequestStart { get; set; } = DateTime.MinValue;
}