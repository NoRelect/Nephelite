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
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<KeyService>();
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(2);
    options.Cookie.HttpOnly = true;
});
builder.Services.AddFido2(options =>
    {
        options.ServerDomain = "localhost";
        options.ServerName = "Localhost";
        options.Origins = new HashSet<string> { "https://localhost:7096 " };
    })
    .AddCachedMetadataService(config =>
    {
        config.AddFidoMetadataRepository();
    });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseSession();
app.UseAuthorization();
app.MapControllers();

app.Run();