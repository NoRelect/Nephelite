var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOptions();
//builder.Services.Configure<PublicKeyCredentialsConfiguration>(builder.Configuration);
builder.Services.Configure<PublicKeyCredentialsConfiguration>(opts =>
{
    opts.Credentials = new List<V1PublicKeyCredentialSpec>
    {
        JsonSerializer.Deserialize<V1PublicKeyCredentialSpec>("""
                                                          {
                                                            "user": "test",
                                                            "credentialId": "Rn0xWtlk8TmUPS9MsQBYKNRdy/U8ugkq490I6cTETz7cyHGnTDFXnzFpB7UYDE7zDWVlpejBK6ElIYPtlM8d2g==",
                                                            "publicKey": "pQECAyYgASFYIIXVvYN3YeWJ1J-IueiaFoL_4p-EfS8ofMznDulVZzwkIlggCXZ86XNEJGGHsDKC7p94e6aa7IA9SngTQNo6fNECbsc"
                                                          }
                                                          """)!
    };
});
builder.Services.Configure<ClientConfiguration>(opts =>
{
    opts.Clients = new List<V1ClientSpec>
    {
        new()
        {
            ClientId = "test",
            ClientSecret = "secret",
            RedirectUrls = new []{ "https://localhost:5000" }
        }
    };
});
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<KeyService>();
builder.Services.AddFido2(options =>
{
    options.ServerDomain = "localhost";
    options.ServerName = "Localhost";
    options.Origins = new HashSet<string> { "https://localhost:7096 " };
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthorization();
app.MapControllers();

app.Run();