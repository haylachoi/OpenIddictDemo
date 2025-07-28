using Microsoft.AspNetCore.Identity;

namespace OpenIddictDemo.Provider.Models;

public class ApplicationUser : IdentityUser<Guid>
{
    [PersonalData]
    public string? Signatrue { get; set; }
}
