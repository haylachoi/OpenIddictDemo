using OpenIddict.Abstractions;
using OpenIddictDemo.Provider.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictDemo.Provider.Services;

public class Worker : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public Worker(IServiceProvider serviceProvider) => _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        await RegisterApplicationsAsync(scope.ServiceProvider);
        await RegisterScopesAsync(scope.ServiceProvider);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static async Task RegisterApplicationsAsync(IServiceProvider provider)
    {
        var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await manager.FindByClientIdAsync("web-client") is null)
        {
            await manager.CreateAsync(
                new OpenIddictApplicationDescriptor
                {
                    ClientId = "web-client",
                    ClientSecret = "web-client-secret",
                    ConsentType = ConsentTypes.Implicit,
                    DisplayName = "Web Client Application",
                    PostLogoutRedirectUris =
                    {
                        new Uri("http://localhost:5236/signout-callback-oidc"),
                        new Uri("https://localhost:7274/signout-callback-oidc"),
                        new Uri("https://localhost:7274"),
                    },
                    RedirectUris =
                    {
                        new Uri("https://localhost:7023"),
                        new Uri("https://localhost:7274/callback/login"),
                        new Uri("https://localhost:7274/signin-oidc"),
                        new Uri("https://oidcdebugger.com/debug"),
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "api",
                    },
                }
            );
        }

        // Register a machine-to-machine client for API access
        if (await manager.FindByClientIdAsync("api-client") is null)
        {
            await manager.CreateAsync(
                new OpenIddictApplicationDescriptor
                {
                    ClientId = "api-client",
                    ClientSecret = "api-client-secret",
                    // ConsentType = ConsentTypes.Implicit,
                    DisplayName = "API Client Application",
                    Permissions =
                    {
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.Prefixes.Scope + "api",
                        Permissions.Endpoints.Introspection,
                        Permissions.Endpoints.Revocation,
                    },
                }
            );
        }
    }

    private static async Task RegisterScopesAsync(IServiceProvider provider)
    {
        var manager = provider.GetRequiredService<IOpenIddictScopeManager>();

        if (await manager.FindByNameAsync("api") is null)
        {
            await manager.CreateAsync(
                new OpenIddictScopeDescriptor
                {
                    Name = "api",
                    DisplayName = "API Access",
                    Description = "Access to the API resources",
                    Resources = { "resource-server" },
                }
            );
        }
    }
}
