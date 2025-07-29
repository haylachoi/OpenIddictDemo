using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddictDemo.Provider.Models;

namespace OpenIddictDemo.Provider.Pages.Account;

public class LoginModel : PageModel
{
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
        if (Username != Constant.Username || Password != Constant.Password)
        {
            ModelState.AddModelError(string.Empty, "Email or password is invalid");
            return Page();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, Constant.Email),
            new(ClaimTypes.NameIdentifier, Username),
        };

        var principal = new ClaimsPrincipal(
            new List<ClaimsIdentity>
            {
                new(claims, CookieAuthenticationDefaults.AuthenticationScheme),
            }
        );

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        if (!string.IsNullOrEmpty(ReturnUrl))
        {
            return Redirect(ReturnUrl);
        }

        return Page();
    }
}
