using System.Collections.Immutable;
using System.Security.Claims;
using System.Web;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddictDemo.Provider.Helper;
using OpenIddictDemo.Provider.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

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
        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
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

        // var providerName = result.Principal.GetClaim(Claims.Private.ProviderName);
        // if (providerName is not null)
        // {
        //     return AcceptExternalLogin(request.GetScopes(), result.Principal);
        // }

        var user =
            await GetUserFromPrincipalAsync(result.Principal)
            ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        var application =
            await _applicationManager.FindByClientIdAsync(request.ClientId)
            ?? throw new InvalidOperationException(
                "Details concerning the calling client application cannot be found."
            );

        var authorizations = await _authorizationManager
            .FindAsync(
                subject: await _userManager.GetUserIdAsync(user),
                client: await _applicationManager.GetIdAsync(application),
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()
            )
            .ToListAsync();

        var consentType = await _applicationManager.GetConsentTypeAsync(application);

        switch (consentType)
        {
            case ConsentTypes.External when authorizations.Count is 0:
                return Forbid(
                    Errors.ConsentRequired,
                    "The logged in user is not allowed to access this client application."
                );

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Count is not 0:
            case ConsentTypes.Explicit
                when authorizations.Count is not 0 && !request.HasPromptValue(PromptValues.Consent):
                var identity = await CreateIdentity(user, request.GetScopes(), null);

                // Automatically create a permanent authorization to avoid requiring explicit consent
                // for future authorization or token requests containing the same scopes.
                var authorization = authorizations.LastOrDefault();
                authorization ??= await _authorizationManager.CreateAsync(
                    identity: identity,
                    subject: await _userManager.GetUserIdAsync(user),
                    client: (await _applicationManager.GetIdAsync(application))!,
                    type: AuthorizationTypes.Permanent,
                    scopes: identity.GetScopes()
                );

                identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(GetDestinations);

                return SignIn(
                    new ClaimsPrincipal(identity),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
                );

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit when request.HasPromptValue(PromptValues.None):
            case ConsentTypes.Systematic when request.HasPromptValue(PromptValues.None):
                return Forbid(Errors.ConsentRequired, "Interactive user consent is required.");

            // In every other case, render the consent form.
            default:
                var returnUrl = HttpUtility.UrlEncode(Request.Path + Request.QueryString);
                var consentRedirectUrl = $"/account/consent?returnUrl={returnUrl}";

                return Redirect(consentRedirectUrl);
        }
    }

    [Authorize, FormValueRequired("submit.Accept")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Accept()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException(
                "The OpenID Connect request cannot be retrieved."
            );

        var user =
            await GetUserFromPrincipalAsync(User)
            ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        var application =
            await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException(
                "Details concerning the calling client application cannot be found."
            );

        var authorizations = await _authorizationManager
            .FindAsync(
                subject: await _userManager.GetUserIdAsync(user),
                client: await _applicationManager.GetIdAsync(application),
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()
            )
            .ToListAsync();

        // Note: the same check is already made in the other action but is repeated
        // here to ensure a malicious user can't abuse this POST-only endpoint and
        // force it to return a valid response without the external authorization.
        if (
            authorizations.Count is 0
            && await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External)
        )
        {
            return Forbid(
                Errors.ConsentRequired,
                "The logged in user is not allowed to access this client application."
            );
        }

        var identity = await CreateIdentity(user, request.GetScopes(), null);

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        var authorization = authorizations.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: identity,
            subject: await _userManager.GetUserIdAsync(user),
            client: (await _applicationManager.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes()
        );

        // AuthorizationId giúp hệ thống truy vết xem token này thuộc về authorization nào, refresh token, revoke token theo session,...
        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

        return SignIn(
            new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
    }

    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    // Notify OpenIddict that the authorization grant has been denied by the resource owner
    // to redirect the user agent to the client application using the appropriate response_mode.
    public IActionResult Deny() =>
        Forbid(Errors.AccessDenied, errorDescription: "The user denied the authorization request.");

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

    // GET: /api/userinfo
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("userinfo"), HttpPost("userinfo"), Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await GetUserFromPrincipalAsync(User);
        if (user == null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(
                    new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                            Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The specified access token is bound to an account that no longer exists.",
                    }
                )
            );
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            [Claims.Subject] = user.Id,
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email;
            claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Phone))
        {
            claims[Claims.PhoneNumber] = await _userManager.GetPhoneNumberAsync(user);
            claims[Claims.PhoneNumberVerified] = await _userManager.IsPhoneNumberConfirmedAsync(
                user
            );
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.FullName ?? $"{user.FirstName} {user.LastName}";
            claims[Claims.GivenName] = user.FirstName;
            claims[Claims.FamilyName] = user.LastName;
            claims[Claims.PreferredUsername] = user.UserName;
            claims[Claims.Birthdate] = user.BirthDate?.ToString("yyyy-MM-dd");
            claims[Claims.Gender] = user.Gender; // assuming "male" / "female" / "other"
            claims[Claims.Locale] = user.Locale; // e.g. "vi-VN"
            claims[Claims.UpdatedAt] = user.UpdatedAt.ToString();
        }

        // Note: the complete list of standard claims supported by the OpenID Connect specification
        // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

        return Ok(claims);
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
            .SetClaim("signatrue", user.Signature)
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
