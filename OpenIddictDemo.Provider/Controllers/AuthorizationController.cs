using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddictDemo.Provider.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictDemo.Provider.Controllers;

[ApiController]
[Route("connect")]
public class AuthorizationController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AuthorizationController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager
    )
        : base()
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("token"), Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenID Connect request không hợp lệ.");
        if (
            request.IsAuthorizationCodeGrantType()
            || request.IsRefreshTokenGrantType()
            || request.IsDeviceCodeGrantType()
        )
        {
            // Retrieve the claims principal stored in the authorization code
            var result = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
            );

            if (
                result is not { Succeeded: true, Principal: not null }
                || await GetUserFromPrincipalAsync(result.Principal) is not { } user
            )
            {
                return Forbid(Errors.InvalidToken, "The token is no longer valid.");
            }

            // Ensure the user is still allowed to sign in.
            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(Errors.InvalidGrant, "The user is no longer allowed to sign in.");
            }

            // lấy thông tin có sẵn từ principal
            var identity = await CreateIdentity(result.Principal, user, GetDestinations);
            var principal = new ClaimsPrincipal(identity);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new NotImplementedException("The specified grant is not implemented.");
    }

    [HttpPost("logout"), HttpGet("logout")]
    public async Task<IActionResult> LogoutPost()
    {
        await HttpContext.SignOutAsync();

        return SignOut(
            authenticationSchemes:
            [
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                IdentityConstants.ApplicationScheme,
            ],
            properties: new AuthenticationProperties { RedirectUri = "/" }
        );
    }

    private ForbidResult Forbid(string error, string errorDescription) =>
        Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(
                new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        errorDescription,
                }
            )
        );

    // dùng email để lấy user sẽ dễ test khi dùng với in memory db, vì thông tin user sẽ dc seed lại khi run app và id sẽ khác nhau
    private Task<ApplicationUser?> GetUserFromPrincipalAsync(ClaimsPrincipal principal)
    {
        // var user =
        //     _userManager.GetUserAsync(principal);

        // ClaimTypes là của asp.net , còn claims là của openIddict
        var email =
            principal.GetClaim(ClaimTypes.Email)
            ?? principal.GetClaim(Claims.Email)
            ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        var user = _userManager.FindByEmailAsync(email);

        return user;
    }

    private async Task<ClaimsIdentity> CreateIdentity(
        ClaimsPrincipal principal,
        ApplicationUser user,
        Func<Claim, IEnumerable<string>> selector
    )
    {
        var identity = new ClaimsIdentity(
            principal.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role
        );

        // override lại nếu user đã đổi thông tin
        identity
            .SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
            .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
            .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
            .SetClaims(Claims.Role, [.. (await _userManager.GetRolesAsync(user))]);

        identity.SetDestinations(selector);

        return identity;
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case "signatrue":
                yield return Destinations.IdentityToken;
                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
