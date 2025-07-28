using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddProblemDetails();
builder.Services.AddOpenApi();

builder
    .Services.AddOpenIddict()
    .AddValidation(options =>
    {
        // Note: the validation handler uses OpenID Connect discovery
        // to retrieve the issuer signing keys used to validate tokens.
        // options.SetIssuer(new Uri("https://provider"));
        var uri = builder.Configuration["services:provider:https:0"];
        options.SetIssuer(new Uri(uri));

        // dùng introspection endpoint khi jwt bị encrypted,... hay khi token bị revoke trước hạn
        options.UseIntrospection();
        options.SetClientId("api-client");
        options.SetClientSecret("api-client-secret");

        // Register the encryption credentials. This sample uses a symmetric
        // encryption key that is shared between the server and the API project.
        //
        // Note: in a real world application, this encryption key should be
        // stored in a safe place (e.g in Azure KeyVault, stored as a secret).
        // options.AddEncryptionKey(new SymmetricSecurityKey(
        //     Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        // dùng http client để tạo request
        options
            .UseSystemNetHttp()
            // dùng thông tin từ assembly, thêm vào header user-agent
            .SetProductInformation(typeof(Program).Assembly);

        // tương tác với asp.net authentication,...
        options.UseAspNetCore();

        // Enable authorization entry validation, which is required to be able
        // to reject access tokens retrieved from a revoked authorization code.
        // options.EnableAuthorizationEntryValidation();
    });

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

builder.Services.AddAuthorizationBuilder();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseAuthentication();
app.UseAuthorization();

string[] summaries =
[
    "Freezing",
    "Bracing",
    "Chilly",
    "Cool",
    "Mild",
    "Warm",
    "Balmy",
    "Hot",
    "Sweltering",
    "Scorching",
];

app.MapGet(
        "/weatherforecast",
        () =>
        {
            var forecast = Enumerable
                .Range(1, 5)
                .Select(index => new WeatherForecast(
                    DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                    Random.Shared.Next(-20, 55),
                    summaries[Random.Shared.Next(summaries.Length)]
                ))
                .ToArray();
            return forecast;
        }
    )
    .RequireAuthorization()
    .WithName("GetWeatherForecast");

app.MapDefaultEndpoints();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
