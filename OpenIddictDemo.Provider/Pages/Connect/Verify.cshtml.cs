using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddictDemo.Provider.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictDemo.Provider.Pages.Connect;

[Authorize]
public class VerifyModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public VerifyModel(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<ApplicationUser> userManager
    )
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _userManager = userManager;
    }

    [BindProperty]
    public string? Error { get; set; }

    [BindProperty]
    public string? ErrorDescription { get; set; }

    [BindProperty]
    public string? ApplicationName { get; set; }

    [BindProperty]
    public string? Scope { get; set; }

    [BindProperty]
    public string? UserCode { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
        if (
            result is { Succeeded: true }
            && !string.IsNullOrEmpty(result.Principal.GetClaim(Claims.ClientId))
        )
        {
            var application = await _applicationManager.FindByClientIdAsync(
                result.Principal.GetClaim(Claims.ClientId)!
            );
            if (application is null)
                throw new InvalidOperationException("Client application not found.");

            ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application);
            Scope = string.Join(" ", result.Principal.GetScopes());
            UserCode = result.Properties?.GetTokenValue(
                OpenIddictServerAspNetCoreConstants.Tokens.UserCode
            );

            return Page();
        }

        if (
            !string.IsNullOrEmpty(
                result.Properties?.GetTokenValue(
                    OpenIddictServerAspNetCoreConstants.Tokens.UserCode
                )
            )
        )
        {
            Error = Errors.InvalidToken;
            ErrorDescription =
                "The specified user code is not valid. Please make sure you typed it correctly.";
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAcceptAsync()
    {
        var email = User.FindFirstValue(ClaimTypes.Email);
        ApplicationUser? user = null;
        if (email is not null)
        {
            user = await _userManager.FindByEmailAsync(email);
        }
        else if (User.FindFirstValue(ClaimTypes.NameIdentifier) is { } username)
        {
            user = await _userManager.FindByNameAsync(username);
        }

        if (user is null)
        {
            throw new InvalidOperationException("User not found.");
        }

        var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
        if (
            result is { Succeeded: true }
            && !string.IsNullOrEmpty(result.Principal.GetClaim(Claims.ClientId))
        )
        {
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role
            );

            identity
                .SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, [.. await _userManager.GetRolesAsync(user)]);

            identity.SetScopes(result.Principal.GetScopes());
            identity.SetResources(
                await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync()
            );
            identity.SetDestinations(_ => [Destinations.AccessToken, Destinations.IdentityToken]);

            var props = new AuthenticationProperties { RedirectUri = "/" };

            return SignIn(
                new ClaimsPrincipal(identity),
                props,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
            );
        }

        Error = Errors.InvalidToken;
        ErrorDescription =
            "The specified user code is not valid. Please make sure you typed it correctly.";
        return Page();
    }

    public IActionResult OnPostDeny()
    {
        return Forbid(
            new AuthenticationProperties { RedirectUri = "/" },
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
    }
}
