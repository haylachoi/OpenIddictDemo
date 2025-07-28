using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddictDemo.Provider.Models;

namespace OpenIddictDemo.Provider.Pages.Account
{
    [Authorize(AuthenticationSchemes = "External")]
    public class RegisterFromExternalProviderModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public RegisterFromExternalProviderModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required]
            [Display(Name = "Tên người dùng")]
            public string Username { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var result =
                await HttpContext.AuthenticateAsync("External")
                ?? throw new InvalidOperationException(
                    "Dữ liệu ủy quyền từ bên ngoài không thể dùng để xác thực."
                );
            ;
            if (!result.Succeeded || result.Principal == null)
            {
                return BadRequest("Không thể xác thực.");
            }

            var provider =
                (string?)
                    result.Properties.GetString(
                        OpenIddictClientAspNetCoreConstants.Properties.ProviderName
                    ) ?? throw new InvalidOperationException("Không có thông tin provider.");
            var providerUserId =
                result.Principal.GetClaim(ClaimTypes.NameIdentifier)
                ?? throw new InvalidOperationException("Không có NameIdentifier từ provider.");

            // Kiểm tra người dùng đã từng login với provider này chưa
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            if (user is not null)
            {
                await _signInManager.SignInAsync(user, isPersistent: true);

                return LocalRedirect(result.Properties?.RedirectUri ?? "/");
            }

            return Page();
        }

        public async Task<IActionResult> OnPost()
        {
            // Lấy thông tin ủy quyền đã được OpenIddict xác thực trong quá trình xử lý callback.
            var result = await HttpContext.AuthenticateAsync("External");
            if (result is not { Succeeded: true, Principal.Identity.IsAuthenticated: true })
            {
                throw new InvalidOperationException(
                    "Dữ liệu ủy quyền từ bên ngoài không thể dùng để xác thực."
                );
            }

            var existing = await _userManager.FindByNameAsync(Input.Username);
            if (existing != null)
            {
                ModelState.AddModelError("Input.Username", "Tên người dùng đã tồn tại.");
                return Page();
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
            var name = result.Principal.GetClaim(ClaimTypes.Name);

            var loginInfo = new UserLoginInfo(provider, providerUserId, provider);

            // Kiểm tra người dùng đã từng login với provider này chưa
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null && email is not null)
            {
                // Nếu chưa có login info, thử tìm bằng email
                user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    user = new ApplicationUser
                    {
                        UserName = Input.Username,
                        Email = email,
                        EmailConfirmed = true, // nếu bạn tin tưởng provider
                        // Bạn có thể gán thêm các field custom khác ở đây nếu cần
                    };
                    var createResult = await _userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                        throw new InvalidOperationException(
                            "Không thể tạo user mới: "
                                + string.Join("; ", createResult.Errors.Select(e => e.Description))
                        );
                }

                // Gắn login info từ provider vào user
                var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
                if (!addLoginResult.Succeeded)
                    throw new InvalidOperationException("Không thể gắn login info vào user.");
            }

            // Đăng nhập người dùng
            await _signInManager.SignInAsync(user, isPersistent: true);

            return LocalRedirect(result.Properties?.RedirectUri ?? "/");
        }
    }
}
