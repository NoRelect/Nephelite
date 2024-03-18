var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<KeyService>();
builder.Services.AddSingleton<KubernetesService>();
builder.Services.Configure<NepheliteConfiguration>(builder.Configuration.GetSection("Nephelite"));
builder.Services.AddSingleton(new Kubernetes(KubernetesClientConfiguration.BuildDefaultConfig()));
builder.Services.AddFido2(builder.Configuration.GetSection("Fido2Config"));

var app = builder.Build();

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapControllers();

app.Run();