using Microsoft.AspNetCore.Identity;
using OpenIddictDemo.Provider.Models;

namespace OpenIddictDemo.Provider;

public static class DbInitializer
{
    public static async Task SeedAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<
            RoleManager<IdentityRole<Guid>>
        >();

        // Tạo role nếu chưa có
        const string roleName = "Admin";
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            await roleManager.CreateAsync(new IdentityRole<Guid>(roleName));
        }

        // Kiểm tra user đã tồn tại
        var email = "admin@example.com";
        var user = await userManager.FindByEmailAsync(email);
        if (user == null)
        {
            var newUser = new ApplicationUser
            {
                UserName = "admin",
                Email = email,
                EmailConfirmed = true,
                Signature = "hehe hoho",
            };

            var result = await userManager.CreateAsync(newUser, "Admin@123456789"); // đặt mật khẩu ở đây

            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(newUser, roleName);
            }
            else
            {
                // xử lý lỗi nếu cần
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                throw new Exception("Không thể tạo user: " + errors);
            }
        }
    }
}
