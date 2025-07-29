using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using OpenIddictDemo.Provider;
using OpenIddictDemo.Provider.Data;
using OpenIddictDemo.Provider.Models;
using OpenIddictDemo.Provider.Services;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

// mã hóa data nhạy cảm như cookie,...
// builder
//     .Services.AddDataProtection()
//     .PersistKeysToFileSystem(new DirectoryInfo(@"/var/keys"))
//     .SetApplicationName("MyApp");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("openiddictdb");
    // options.UseNpgsql(connectionString);
    options.UseInMemoryDatabase("test");
    options.UseOpenIddict<Guid>();
});

builder
    .Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Bị khóa trong 5 phút
        options.Lockout.MaxFailedAccessAttempts = 2; // Sau 2 lần sai sẽ bị khóa
        options.Lockout.AllowedForNewUsers = true; // Cho phép áp dụng cho cả user mới
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
// (like pruning orphaned authorizations/tokens from the database) at regular intervals.
builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore();
});

// Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

// Register the OpenIddict core components.
builder
    .Services.AddOpenIddict()
    .AddCore(options =>
    {
        options
            .UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>()
            // ko cần nếu ko dùng custom key
            .ReplaceDefaultEntities<Guid>();

        options.UseQuartz();
    })
    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Enable the authorization and token endpoints.
        options
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetIntrospectionEndpointUris("/connect/introspect")
            .SetUserInfoEndpointUris("/connect/userinfo")
            .SetEndSessionEndpointUris("/connect/logout")
            .SetRevocationEndpointUris("/connect/revoke");

        options.RequireProofKeyForCodeExchange();
        // hiển thị trong discovery document.
        options.RegisterScopes(
            "api",
            Scopes.Email,
            Scopes.Profile,
            Scopes.Roles,
            // cấp refresh token
            Scopes.OfflineAccess,
            Scopes.OpenId
        );

        // options.RegisterClaims();

        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(20));
        options.SetRefreshTokenLifetime(TimeSpan.FromDays(20));

        options.AcceptAnonymousClients();

        // options.RequirePushedAuthorizationRequests();
        // options.SetPushedAuthorizationEndpointUris("connect/par");

        options.EnableAuthorizationRequestCaching();
        options.EnableEndSessionRequestCaching();

        // options.DisableAudienceValidation();
        // options.DisableScopeValidation();
        // options.DisableResourceValidation();

        options
            .AllowAuthorizationCodeFlow()
            .AllowClientCredentialsFlow()
            .AllowPasswordFlow()
            .AllowRefreshTokenFlow();

        options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();
        options.DisableAccessTokenEncryption();

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            // custom endpoint hoạt động nếu enable passthrough, nếu ko enable thì phải tạo event handler
            // enable passthrough cũng cho phép request đi qua các pipeline
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableStatusCodePagesIntegration();

        // bật chế độ “reference token” cho Refresh Token, thay vì chế độ mặc định là self-contained token.
        // khi bật refresh token sẽ là Guid chứ ko phải là jwt, bảo mật hơn nhưng chậm hơn
        // options.UseReferenceRefreshTokens();

        // nếu add event thì ko cần phải tự tạo endpoint nữa, nếu đã tạo endpoint thị event sẽ chạy sau khi endpoint xử lý xong
        // có thể tách event handler ra bằng cách tạo class kế thừa OpenIddictServerEvents.HandleTokenRequestContext

        // options.AddEventHandler<OpenIddictServerEvents.HandleTokenRequestContext>(builder =>
        // {
        //     builder.UseInlineHandler(context =>
        //     {
        //         var grantType = context.Request.GrantType;

        //         if (grantType == OpenIddictConstants.GrantTypes.Password)
        //         {
        //             var username = context.Request.Username;
        //             var password = context.Request.Password;

        //             // ✳️ Validate user
        //             if (username != "test" || password != "1234")
        //             {
        //                 context.Reject(
        //                     error: OpenIddictConstants.Errors.InvalidGrant,
        //                     description: "Invalid username or password."
        //                 );
        //                 return default;
        //             }

        //             var identity = new ClaimsIdentity(
        //                 OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        //             );
        //             identity.AddClaim(OpenIddictConstants.Claims.Subject, username);
        //             identity.AddClaim(OpenIddictConstants.Claims.Email, "admin@example.com");

        //             foreach (var claim in identity.Claims)
        //                 claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);

        //             context.SignIn(new ClaimsPrincipal(identity));
        //             return default;
        //         }

        //         if (grantType == OpenIddictConstants.GrantTypes.ClientCredentials)
        //         {
        //             var clientId = context.ClientId;

        //             // ✳️ Validate clientId (tuỳ bạn muốn kiểm tra thêm gì không)
        //             if (string.IsNullOrEmpty(clientId))
        //             {
        //                 context.Reject(
        //                     error: OpenIddictConstants.Errors.InvalidClient,
        //                     description: "Missing client_id."
        //                 );
        //                 return default;
        //             }

        //             var identity = new ClaimsIdentity(
        //                 OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        //             );
        //             identity.AddClaim(OpenIddictConstants.Claims.Subject, clientId);

        //             foreach (var claim in identity.Claims)
        //                 claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);

        //             context.SignIn(new ClaimsPrincipal(identity));
        //             return default;
        //         }

        //         return default;
        //     });
        // });
    })
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        // dùng cho api cùng project với openiddict server
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();

        // Enable authorization entry validation, which is required to be able
        // to reject access tokens retrieved from a revoked authorization code.
        // options.EnableAuthorizationEntryValidation();
    })
    .AddClient(options =>
    {
        // Note: this sample uses the code flow, but you can enable the other flows if necessary.
        options.AllowAuthorizationCodeFlow();

        // Register the signing and encryption credentials used to protect
        // sensitive data like the state tokens produced by OpenIddict.
        options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            .EnableStatusCodePagesIntegration()
            .EnableRedirectionEndpointPassthrough();

        // Register the System.Net.Http integration and use the identity of the current
        // assembly as a more specific user agent, which can be useful when dealing with
        // providers that use the user agent as a way to throttle requests (e.g Reddit).
        options.UseSystemNetHttp().SetProductInformation(typeof(Program).Assembly);

        // Register the Web providers integrations.
        //
        // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
        // URI per provider, unless all the registered providers support returning a special "iss"
        // parameter containing their URL as part of authorization responses. For more information,
        // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
        options
            .UseWebProviders()
            .AddGitHub(options =>
            {
                options
                    .SetClientId("Ov23litwCY0frQstep4Q")
                    .SetClientSecret("691fbe986db152eded6c93f1856bece26228e116")
                    .SetRedirectUri("callback/login/github");
            });
    });

// Add authentication services
builder
    .Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
        options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
    })
    .AddCookie("External");

builder.Services.AddControllers();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Register the worker responsible for seeding the database.
builder.Services.AddHostedService<Worker>();

builder.Services.AddRazorPages();

var app = builder.Build();

await app.Services.SeedAsync();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    await app.MigrateDbContextAsync<ApplicationDbContext>();
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapControllers();
app.MapRazorPages().WithStaticAssets();

app.MapGet(
    "/challenge/github",
    async (HttpContext context, string? returnUrl) =>
    {
        return TypedResults.Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl ?? "/" },
            authenticationSchemes: [Providers.GitHub]
        );
    }
);

app.MapDefaultEndpoints();

app.Run();
