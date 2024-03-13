namespace Nephelite.Model;

public class SessionInformation
{
    public AuthorizationRequest AuthorizationRequest { get; set; } = default!;
    
    public AssertionOptions AssertionOptions { get; set; } = default!;

    public DateTime RequestStart { get; set; } = DateTime.MinValue;
}