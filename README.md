Demo authentication code flow with PKCE.
#### Server
- đăng ký client với client type là public, response type là code, require PKCE
- bật require PKCE trong config openiddict

#### Web client
- Không config với client secret
- UsePkce trong config OIDC