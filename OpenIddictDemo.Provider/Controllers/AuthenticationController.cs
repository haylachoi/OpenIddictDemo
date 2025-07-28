using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddictDemo.Provider.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictDemo.Provider.Controllers;

// Có nhiều cách xử lý callback OAuth 2.0/OpenID Connect, mỗi cách có ưu và nhược điểm riêng:
//
//   * Sử dụng trực tiếp token để thực hiện các hành động thay mặt người dùng. Phù hợp với
//     ứng dụng không cần truy cập dài hạn hoặc không muốn lưu access/refresh token vào DB hay cookie
//     (vì lý do bảo mật). Cũng phù hợp với ứng dụng chỉ cần gọi API thay mặt người dùng, không cần xác thực người dùng.
//
//   * Lưu thông tin claims/token vào cơ sở dữ liệu (và có thể giữ lại các claims quan trọng trong cookie
//     để tránh vượt giới hạn dung lượng cookie). Với ASP.NET Core Identity, có thể dùng API
//     `UserManager.SetAuthenticationTokenAsync()` để lưu token ngoài.
//
//     Lưu ý: trong trường hợp này nên dùng mã hóa cột để bảo vệ token trong DB.
//
//   * Lưu claims/token trong cookie xác thực, không cần DB người dùng nhưng có thể bị giới hạn dung lượng cookie
//     bởi trình duyệt (VD: Safari giới hạn 4KB/cookie cho mỗi domain).
//
//     Lưu ý: đây là cách đang dùng, nhưng các claim ngoài sẽ được lọc chỉ giữ lại những thông tin như user id.
//     Access/refresh token cũng được xử lý tương tự.

// Quan trọng: nếu server bên ngoài không hỗ trợ OpenID Connect và không có userinfo endpoint,
// thì result.Principal.Identity sẽ là identity chưa xác thực và không chứa bất kỳ claim người dùng nào.
//
// Các identity như vậy không thể dùng trực tiếp để tạo authentication cookie trong ASP.NET Core
// (vì hệ thống chống CSRF yêu cầu ít nhất phải có name claim để gắn CSRF cookie với danh tính người dùng).
// Nhưng access/refresh token vẫn có thể lấy bằng `result.Properties.GetTokens()` để gọi API.
public class AuthenticationController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AuthenticationController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager
    )
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [
        HttpGet("~/callback/login/{provider}"),
        HttpPost("~/callback/login/{provider}"),
        IgnoreAntiforgeryToken
    ]
    public async Task<ActionResult> LogInCallback()
    {
        // Lấy thông tin ủy quyền đã được OpenIddict xác thực trong quá trình xử lý callback.
        var result = await HttpContext.AuthenticateAsync(
            OpenIddictClientAspNetCoreDefaults.AuthenticationScheme
        );

        if (result is not { Succeeded: true, Principal.Identity.IsAuthenticated: true })
        {
            throw new InvalidOperationException(
                "Dữ liệu ủy quyền từ bên ngoài không thể dùng để xác thực."
            );
        }

        var provider =
            (string?)
                result.Properties.GetString(
                    OpenIddictClientAspNetCoreConstants.Properties.ProviderName
                ) ?? throw new InvalidOperationException("Không có thông tin provider.");
        var providerUserId =
            result.Principal.GetClaim(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("Không có NameIdentifier từ provider.");

        var email = result.Principal.GetClaim(ClaimTypes.Email);


        // Kiểm tra người dùng đã từng login với provider này chưa
        var user = await _userManager.FindByLoginAsync(provider, providerUserId);

        if (user == null && email is not null)
        {
            // Nếu chưa có login info, thử tìm bằng email
            user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                var principal = result.Principal;
                var properties = result.Properties;

                // Lưu tạm vào cookie với authentication scheme riêng (ví dụ: "External")
                await HttpContext.SignInAsync("External", principal, properties);

                return LocalRedirect("/Account/RegisterFromExternalProvider");
            }
        }

        // Đăng nhập người dùng
        await _signInManager.SignInAsync(user, isPersistent: true);

        return LocalRedirect(result.Properties?.RedirectUri ?? "/");

        // // Tạo ClaimsIdentity dựa trên thông tin từ bên ngoài để dùng trong authentication cookie.
        // var identity = new ClaimsIdentity(
        //     authenticationType: "ExternalLogin",
        //     nameType: ClaimTypes.Name,
        //     roleType: ClaimTypes.Role
        // );

        // // Mặc định, OpenIddict sẽ tự ánh xạ các claim như email/name và name identifier
        // // từ định dạng chuẩn OpenID Connect hoặc định dạng riêng của provider.
        // // Nếu cần, có thể lấy thêm các claim khác từ identity và đưa vào cookie.
        // identity
        //     .SetClaim(ClaimTypes.Email, result.Principal.GetClaim(ClaimTypes.Email))
        //     .SetClaim(ClaimTypes.Name, result.Principal.GetClaim(ClaimTypes.Name))
        //     .SetClaim(
        //         ClaimTypes.NameIdentifier,
        //         result.Principal.GetClaim(ClaimTypes.NameIdentifier)
        //     );

        // // Lưu lại thông tin đăng ký để dùng sau này.
        // identity
        //     .SetClaim(
        //         Claims.Private.RegistrationId,
        //         result.Principal.GetClaim(Claims.Private.RegistrationId)
        //     )
        //     .SetClaim(
        //         Claims.Private.ProviderName,
        //         result.Principal.GetClaim(Claims.Private.ProviderName)
        //     );

        // // Quan trọng: nếu dùng ASP.NET Core Identity và giao diện mặc định của nó,
        // // thì identity tạo ở đây **không được lưu trực tiếp vào cookie xác thực cuối cùng** (gọi là "application cookie")
        // // mà chỉ lưu vào "external cookie" tạm thời. Cookie cuối được tạo sau bởi Razor Page `ExternalLogin`
        // // thông qua `SignInManager.ExternalLoginSignInAsync()`.
        // //
        // // Rất tiếc, quá trình này sẽ **không giữ lại các claims đã thêm ở đây**,
        // // nên bạn không thể đưa claims từ provider bên ngoài vào cookie cuối.
        // //
        // // Nếu cần giữ claims, có thể lưu vào DB của Identity bằng `UserManager.AddClaimAsync()`
        // // hoặc sửa Razor Page `ExternalLogin.cshtml`:
        // // https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/additional-claims#add-and-update-user-claims.
        // //
        // // Ngoài ra, có thể sửa `ExternalLogin.cshtml` để không dùng `ExternalLoginSignInAsync()`
        // // mà dùng thủ công `SignInAsync()` để giữ lại claims.
        // // Nếu không tiện sửa UI, có thể dùng custom `SignInManager` override `SignInOrTwoFactorAsync()` để thay đổi behavior.
        // //
        // // Tham khảo thêm:
        // // - https://haacked.com/archive/2019/07/16/external-claims/
        // // - https://stackoverflow.com/questions/42660568/asp-net-core-identity-extract-and-save-external-login-tokens-and-add-claims-to-l/42670559#42670559

        // // Tạo AuthenticationProperties từ thông tin có sẵn khi thực hiện challenge.
        // var properties = new AuthenticationProperties(result.Properties.Items)
        // {
        //     RedirectUri = result.Properties.RedirectUri ?? "/",

        //     // Đặt thời điểm tạo và hết hạn của ticket là null để tránh phụ thuộc vào thời gian sống của token.
        //     // Cookie handler sẽ tự đặt thời hạn theo cấu hình đã định.
        //     //
        //     // Nếu muốn gắn thời gian sống của cookie với thời gian của identity token từ provider,
        //     // có thể bỏ comment hai dòng này.
        //     IssuedUtc = null,
        //     ExpiresUtc = null,

        //     // Ghi chú: cờ này xác định cookie sẽ là session cookie (xóa khi đóng trình duyệt)
        //     // hay persistent cookie (lưu lâu dài). Dù kiểu gì thì thời hạn thực tế của ticket
        //     // luôn được mã hóa, không thể giả mạo.
        //     IsPersistent = false,
        // };

        // // Frontchannel: tương tác thông qua trình duyệt (người dùng), ví dụ chuyển hướng người dùng sang trang đăng nhập.
        // // Backchannel: tương tác phía server (không qua trình duyệt), ví dụ như gọi API để lấy thông tin người dùng.
        // // Nếu cần, có thể lưu token trong cookie xác thực.
        // // Token không dùng sẽ bị lọc bỏ để giảm dung lượng.
        // properties.StoreTokens(
        //     result
        //         .Properties.GetTokens()
        //         .Where(token =>
        //             token.Name
        //                 is OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken
        //                     or OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken
        //         )
        // );

        // // Gọi handler đăng nhập mặc định để tạo cookie mới và chuyển hướng về URL ban đầu.
        // //
        // // Nếu không muốn dùng handler mặc định, có thể chỉ định tên scheme cụ thể tại đây.
        // return SignIn(new ClaimsPrincipal(identity), properties);
    }
}
