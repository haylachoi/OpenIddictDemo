using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;
using OpenIddictDemo.Device;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = Host.CreateApplicationBuilder(args);

var services = builder.Services;
var providerUri = builder.Configuration["services:provider:https:0"];

services
    .AddOpenIddict()
    // Register the OpenIddict client components.
    .AddClient(options =>
    {
        options.AllowDeviceAuthorizationFlow();

        // Disable token storage, which is not necessary for the device authorization flow.
        options.DisableTokenStorage();

        options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();

        options.UseSystemNetHttp().SetProductInformation(typeof(Program).Assembly);

        // Add a client registration matching the client application definition in the server project.
        options.AddRegistration(
            new OpenIddictClientRegistration
            {
                Issuer = new Uri(providerUri, UriKind.Absolute),

                ClientId = "device",
                Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess },
            }
        );
    });

// Register the background service responsible for handling the console interactions.
services.AddHostedService<InteractiveService>();

// Prevent the console lifetime manager from writing status messages to the output stream.
services.Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true);

// ✅ Cấu hình logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.None); // Tắt "Application started"...
builder.Logging.AddFilter("Microsoft", LogLevel.Warning);
builder.Logging.AddFilter("System", LogLevel.Warning);
builder.Logging.SetMinimumLevel(LogLevel.Warning); // Bỏ Info trở xuống

var app = builder.Build();
await app.RunAsync();
