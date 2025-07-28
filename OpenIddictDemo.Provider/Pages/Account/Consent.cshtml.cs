using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace OpenIddictDemo.Provider.Pages.Account
{
    // [Authorize]
    public class ConsentModel : PageModel
    {
        [BindProperty]
        public string? ReturnUrl { get; set; }

        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }
    }
}
