using Microsoft.AspNetCore.Identity;

namespace OpenIddictDemo.Provider.Models;

public class ApplicationUser : IdentityUser<Guid>
{
    [PersonalData]
    public string? Signature { get; set; }
    [PersonalData]
    public string? FirstName { get; set; }

    [PersonalData]
    public string? LastName { get; set; }

    [PersonalData]
    public string? FullName { get; set; }

    [PersonalData]
    public string? Gender { get; set; } // "male", "female", "other"

    [PersonalData]
    public DateTime? BirthDate { get; set; }

    [PersonalData]
    public string? Locale { get; set; } // e.g., "vi-VN"

    [PersonalData]
    public DateTimeOffset? UpdatedAt { get; set; }
}
