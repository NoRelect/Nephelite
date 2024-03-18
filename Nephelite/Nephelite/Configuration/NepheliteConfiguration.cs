namespace Nephelite.Configuration;

public class NepheliteConfiguration
{
    public string Host { get; set; } = default!;
    public TimeSpan DefaultTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
}