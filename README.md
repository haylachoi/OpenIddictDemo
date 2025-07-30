Nhánh main gồm credentials flow, password flow, authorization code flow

##### Lưu ý khi đăng ký client trong server
- Trong nhiều flow, nếu client type được đăng ký là public trong server thì không cần gửi client_secret(gửi kèm sẽ báo lỗi), còn nếu là confidential thì phải gửi client_secret.

- Mặc dù PKCE được thiết kế để client ko cần gửi client_secret nhưng nếu đăng ký client là confidential trong serrver thì vẫn phải gửi client_secret. Vậy nên nếu dùng PKCE thì nên đăng ký client là public.

##### Phân biệt Claims và ClaimType
- ClaimType là của ASP.NET Identity. 
- Claims là của OpenIddict. Khi signin với OIDC hãy dùng claims.

##### Lưu ý khi tạo ClaimsIdentity
- Mặc định khi tạo identity với claims, các thông tin này sẽ Không xuất hiện trong access_token, id_token.
- `identity.SetDestinations()` sẽ quyết định Claims có xuất hiện trong access_token, id_token ko.
- `identity.SetResources()` sẽ set audience(aud) cho token.