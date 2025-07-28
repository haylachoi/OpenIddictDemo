using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddictDemo.Web;
using OpenIddictDemo.Web.Components;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorComponents().AddInteractiveServerComponents();

builder.Services.AddOutputCache();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<TokenHandler>();
builder
    .Services.AddHttpClient<WeatherApiClient>(client =>
    {
        // This URL uses "https+http://" to indicate HTTPS is preferred over HTTP.
        // Learn more about service discovery scheme resolution at https://aka.ms/dotnet/sdschemes.
        client.BaseAddress = new("https+http://apiservice");
    })
    .AddHttpMessageHandler<TokenHandler>();
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
            // thêm vào header user-agent
            // .SetProductInformation("OpenIddictDemo.Web", "1.0.0")
            // dùng thông tin từ assembly, thêm vào header user-agent
            .SetProductInformation(typeof(Program).Assembly);

        // tương tác với asp.net authentication,...
        options.UseAspNetCore();

        // Enable authorization entry validation, which is required to be able
        // to reject access tokens retrieved from a revoked authorization code.
        // options.EnableAuthorizationEntryValidation();
    });

builder
    .Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        // đọc thông tin config trong
        // https://learn.microsoft.com/en-us/aspnet/core/blazor/security/blazor-web-app-with-oidc?view=aspnetcore-9.0&pivots=non-bff-pattern
        var uri = builder.Configuration["services:provider:https:0"];
        options.Authority = uri;
        options.ClientId = "web-client";
        options.ClientSecret = "web-client-secret";

        // options.Scope.Clear();
        //options.Scope.Add(OpenIdConnectScope.OpenIdProfile);
        options.Scope.Add(OpenIdConnectScope.OfflineAccess);

        // callbackpath và SignedOutCallbackPath phải được đăng ký với client trong identity server
        //
        options.CallbackPath = "/signin-oidc"; // default
        // Đường dẫn OIDC provider gọi lại sau đăng xuất.
        options.SignedOutCallbackPath = "/signout-callback-oidc"; //default
        // Nơi người dùng được chuyển hướng đến cuối cùng sau khi xử lý đăng xuất, (nếu dã chỉ định return_uri trong SignOutAsync rồi thì return_uri sẽ dc ưu tiên))
        options.SignedOutRedirectUri = "/";

        // dùng để logout từ xa. Như 1 app logout, sẽ kéo toàn bộ app khác logout
        options.RemoteSignOutPath = "/signout-oidc";

        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ResponseType = OpenIdConnectResponseType.Code;

        // lưu token trong AuthenticationProperties
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        // để refresh metadata từ discovery endpoint
        // options.RefreshInterval = TimeSpan.FromMinutes(30);

        options.Events = new OpenIdConnectEvents
        {
            OnRemoteFailure = context =>
            {
                // Xử lý lỗi từ server (ví dụ: access_denied)
                if (context.Failure is OpenIdConnectProtocolException)
                {
                    // Redirect người dùng về trang lỗi thân thiện
                    // context.Response.Redirect(
                    //     "/error?message=" + Uri.EscapeDataString(context.Failure.Message)
                    // );

                    context.Response.Redirect("/");
                    context.HandleResponse(); // Ngăn framework văng exception
                }

                return Task.CompletedTask;
            },
        };

        // nếu là true sẽ tự động map Claims(của OIDC) sang claimType(của asp.net)
        options.MapInboundClaims = false;

        options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.UseIfAvailable;

        options.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
        options.TokenValidationParameters.RoleClaimType = "roles";
    });

builder.Services.AddSingleton<CookieOidcRefresher>();

// refresh token
builder
    .Services.AddOptions<CookieAuthenticationOptions>(
        CookieAuthenticationDefaults.AuthenticationScheme
    )
    .Configure<CookieOidcRefresher>(
        (cookieOptions, refresher) =>
        {
            // chạy mỗi khi cần xác thực ( tức là vào endpoint có [Authorize] attribute hoặc gọi User trong pipeline))
            cookieOptions.Events.OnValidatePrincipal = context =>
                refresher.ValidateOrRefreshCookieAsync(
                    context,
                    OpenIdConnectDefaults.AuthenticationScheme
                );
        }
    );

builder.Services.AddAuthorizationBuilder();
builder.Services.AddCascadingAuthenticationState();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.UseOutputCache();

app.MapStaticAssets();

app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.MapGet(
        "/login",
        async (HttpContext context, string? returnUrl) =>
        {
            return TypedResults.Challenge(GetAuthProperties(context, returnUrl));
        }
    )
    .AllowAnonymous();

app.MapPost(
        "/logout",
        async (HttpContext context, [FromForm] string? returnUrl) =>
        {
            return TypedResults.SignOut(
                GetAuthProperties(context, returnUrl),
                [
                    OpenIdConnectDefaults.AuthenticationScheme,
                    CookieAuthenticationDefaults.AuthenticationScheme,
                ]
            );
        }
    )
    .RequireAuthorization()
    .DisableAntiforgery();

// dùng cho remote sign-out
app.MapGet(
    "/signout-oidc",
    async (HttpContext ctx) =>
    {
        await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
);

app.MapGet(
    "/signout-callback-oidc",
    async (HttpContext context) =>
    {
        return Results.Ok();
    }
);

app.MapDefaultEndpoints();

app.Run();

static AuthenticationProperties GetAuthProperties(HttpContext httpContext, string? returnUrl)
{
    var pathBase = httpContext.Request.PathBase.HasValue ? httpContext.Request.PathBase.Value : "/";

    // Nếu returnUrl rỗng hoặc null, sử dụng fallback là PathBase ("/" hoặc prefix như "/app")
    if (string.IsNullOrEmpty(returnUrl))
    {
        returnUrl = pathBase;
    }
    // Nếu là chuỗi URL tuyệt đối không hợp lệ hoặc nghi ngờ, chỉ lấy PathAndQuery
    else if (!Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
    {
        try
        {
            var absoluteUri = new Uri(returnUrl, UriKind.Absolute);
            returnUrl = absoluteUri.PathAndQuery;
        }
        catch
        {
            // Nếu không thể parse, fallback về pathBase để đảm bảo an toàn
            returnUrl = pathBase;
        }
    }
    // Nếu là đường dẫn tương đối hợp lệ nhưng không bắt đầu bằng "/", thêm prefix "/"
    else if (returnUrl[0] != '/')
    {
        returnUrl = $"{pathBase}{returnUrl}";
    }

    // Trả về AuthenticationProperties với RedirectUri được xác thực
    return new AuthenticationProperties { RedirectUri = returnUrl };
}
