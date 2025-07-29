using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddictDemo.Provider;
using OpenIddictDemo.Provider.Data;
using OpenIddictDemo.Provider.Models;
using OpenIddictDemo.Provider.Services;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("openiddictdb");
    options.UseInMemoryDatabase("test");
    options.UseOpenIddict();
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
        options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();

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
        options.EnableAuthorizationRequestCaching();
        options.EnableEndSessionRequestCaching();

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
    });

// Add authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
});

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

app.MapDefaultEndpoints();

app.Run();
