using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddictDemo.Provider.Models;

namespace OpenIddictDemo.Provider.Pages.Account;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager
    )
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [BindProperty]
    public string Username { get; set; } = string.Empty;

    [BindProperty]
    public string Password { get; set; } = string.Empty;

    [BindProperty]
    public string? ReturnUrl { get; set; }

    public IActionResult OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        var user = await _userManager.FindByNameAsync(Username);

        var result = await _signInManager.PasswordSignInAsync(
            Username,
            Password,
            isPersistent: false, // remember me
            lockoutOnFailure: true // cho phép khóa nếu sai nhiều lần
        );

        if (result.Succeeded)
        {
            return !string.IsNullOrEmpty(ReturnUrl)
                ? Redirect(ReturnUrl)
                : RedirectToPage("/Index");
        }

        if (result.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty, "Tài khoản đã bị khóa. Vui lòng thử lại sau.");
        }
        else if (result.IsNotAllowed)
        {
            ModelState.AddModelError(string.Empty, "Tài khoản chưa được kích hoạt.");
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Tên đăng nhập hoặc mật khẩu không đúng.");
        }

        return Page();
    }
}
