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
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager
    )
        : base()
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("token"), Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenID Connect request không hợp lệ.");
        if (request.IsClientCredentialsGrantType())
        {
            var application =
                await _applicationManager.FindByClientIdAsync(request.ClientId)
                ?? throw new InvalidOperationException("The application cannot be found.");

            var identity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType,
                Claims.Name,
                Claims.Role
            );

            identity.SetScopes(request.GetScopes());

            // set audience
            identity.SetResources(
                await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync()
            );

            identity.SetClaim(
                Claims.Subject,
                await _applicationManager.GetClientIdAsync(application)
            );
            identity.SetClaim(
                Claims.Name,
                await _applicationManager.GetDisplayNameAsync(application)
            );

            // mặc định claim ko xuất hiện trong access_token, id_token, hàm này sẽ quyết định claim có xuất hiện trong đó ko
            identity.SetDestinations(GetDestinations);

            return SignIn(
                new ClaimsPrincipal(identity),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
            );
        }

        if (request.IsPasswordGrantType())
        {
            var user = await _userManager.FindByNameAsync(request.Username!);
            if (user == null)
            {
                return Forbid(Errors.InvalidGrant, "The username/password couple is invalid.");
            }

            var result = await _signInManager.CheckPasswordSignInAsync(
                user,
                request.Password!,
                lockoutOnFailure: true
            );

            if (!result.Succeeded)
            {
                return Forbid(Errors.InvalidGrant, "The username/password couple is invalid.");
            }

            var identity = await CreateIdentity(user, request.GetScopes(), GetDestinations);
            var principal = new ClaimsPrincipal(identity);

            principal.SetScopes(request.GetScopes());
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        if (request.IsAuthorizationCodeGrantType())
        {
            // Retrieve the claims principal stored in the authorization code
            var result =
                await HttpContext.AuthenticateAsync(
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
                )
                ?? throw new InvalidOperationException(
                    "The authorization code is no longer valid."
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
            var identity = CreateIdentity(result.Principal);
            var principal = new ClaimsPrincipal(identity);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsRefreshTokenGrantType())
        {
            // refresh token đã được validate trước đó
            var result = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
            );

            var user = await GetUserFromPrincipalAsync(result.Principal);
            if (user == null)
            {
                return Forbid(Errors.InvalidGrant, "The refresh token is no longer valid.");
            }

            // Ensure the user is still allowed to sign in.
            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(Errors.InvalidGrant, "The user is no longer allowed to sign in.");
            }

            var identity = await CreateIdentity(user, request.GetScopes(), GetDestinations);

            return SignIn(
                new ClaimsPrincipal(identity),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
            );
        }
        throw new NotImplementedException("The specified grant is not implemented.");
    }

    [HttpPost("authorize"), HttpGet("authorize"), Produces("application/json")]
    public async Task<IActionResult> Authorize()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenID Connect request không hợp lệ.");

        var result = await HttpContext.AuthenticateAsync();
        if (
            result is not { Succeeded: true }
            || (
                (
                    request.HasPromptValue(PromptValues.Login)
                    || request.MaxAge is 0
                    || (
                        request.MaxAge is not null
                        && result.Properties?.IssuedUtc is not null
                        && TimeProvider.System.GetUtcNow() - result.Properties.IssuedUtc
                            > TimeSpan.FromSeconds(request.MaxAge.Value)
                    )
                // authorize này sẽ dc gọi 2 lần, lần đầu challenge để login, lần 2 thì ko cần challenge nữa
                ) && TempData["IgnoreAuthenticationChallenge"] is null or false
            )
        )
        {
            // If the client application requested promptless authentication,
            // return an error indicating that the user is not logged in.
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(Errors.LoginRequired, "The user is not logged in.");
            }

            TempData["IgnoreAuthenticationChallenge"] = true;
            return Challenge(
                new AuthenticationProperties
                {
                    RedirectUri =
                        Request.PathBase
                        + Request.Path
                        + QueryString.Create(
                            Request.HasFormContentType ? Request.Form : Request.Query
                        ),
                }
            );
        }

        var user =
            await GetUserFromPrincipalAsync(result.Principal)
            ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        var application =
            await _applicationManager.FindByClientIdAsync(request.ClientId)
            ?? throw new InvalidOperationException(
                "Details concerning the calling client application cannot be found."
            );

        var consentType = await _applicationManager.GetConsentTypeAsync(application);

        if (consentType != ConsentTypes.Implicit)
        {
            return Forbid(Errors.InvalidClient, "Only implicit consent clients are supported");
        }

        var identity = await CreateIdentity(user, request.GetScopes(), GetDestinations);
        return SignIn(
            new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
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
        var email =
            principal.GetClaim(ClaimTypes.Email)
            ?? principal.GetClaim(Claims.Email)
            ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        var user = _userManager.FindByEmailAsync(email);

        return user;
    }

    private async Task<ClaimsIdentity> CreateIdentity(
        ApplicationUser user,
        ImmutableArray<string>? scopes,
        Func<Claim, IEnumerable<string>>? selector
    )
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            //claim type nào sẽ được dùng làm username khi gọi identity.Name
            nameType: Claims.Name,
            // claim type nào sẽ được dùng làm role khi gọi identity.IsInRole(...)
            roleType: Claims.Role
        );

        var userIdTask = _userManager.GetUserIdAsync(user);
        var emailTask = _userManager.GetEmailAsync(user);
        var userNameTask = _userManager.GetUserNameAsync(user);
        var rolesTask = _userManager.GetRolesAsync(user);

        await Task.WhenAll(userIdTask, emailTask, userNameTask, rolesTask);

        identity
            .SetClaim(Claims.Subject, userIdTask.Result)
            .SetClaim(Claims.Email, emailTask.Result)
            .SetClaim(Claims.Name, userNameTask.Result)
            .SetClaim(Claims.PreferredUsername, userNameTask.Result)
            .SetClaim("signatrue", user.Signatrue)
            .SetClaims(Claims.Role, [.. rolesTask.Result]);

        if (scopes is not null)
        {
            identity.SetScopes(scopes);
            identity.SetResources(
                await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync()
            );
        }

        if (selector is not null)
        {
            identity.SetDestinations(selector);
        }

        return identity;
    }

    private ClaimsIdentity CreateIdentity(ClaimsPrincipal principal)
    {
        var identity = new ClaimsIdentity(
            principal.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role
        );

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
