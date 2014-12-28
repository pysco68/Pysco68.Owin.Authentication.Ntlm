# Pysco68.Owin.Authentication.NTLM

A passive NTLM autentication middleware for OWIN. This middleware enables you to use NTLM authentication 
independently of IIS or HTTPListener. Additionally, being a passive middleware, it will enable you to use 
local application accounts with Windows Authentication as yet anoter mean of authentication!

## Usage

After installing the package as a dependency in your project you can

```C#
using Pysco68.Owin.Authentication.Ntlm;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;

public class Startup
{
	public void Configuration(IAppBuilder app)
	{
		// use default sign in with application cookies
		app.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationTypes.ApplicationCookie);

		app.UseCookieAuthentication(new CookieAuthenticationOptions()
		{
			AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie                
		});

		// Enable NTLM authentication
		app.UseNtlmAuthentication();

		// .....
	}
}
```

Please note that beause of the slightly unusual way NTLM works (from OWIN perspective) you have to take care
that the CookieAuthentication middleware isn't applying redirects when this middleware returns a 401 during the
first two steps of authentication.

```C#
app.UseCookieAuthentication(new CookieAuthenticationOptions()
{
	AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie 
	LoginPath = new PathString("/api/account/ntlmlogin"),
	Provider = new CookieAuthenticationProvider()
	{
		OnApplyRedirect = ctx =>
		{
			if (!ctx.Request.IsNtlmAuthenticationCallback())    // <------
			{
				ctx.Response.Redirect(ctx.RedirectUri);
			}
		}
	}
});            
```

So make sure to check the above if you get strange redirects or redirect loops!

## Kudos

Big thanks to Nancy.Authentication.Ntlm (https://github.com/toolchain/Nancy.Authentication.Ntlm) for their implementation of Ntlm for Nancy. 
It was a huge help!

## Help / Contribution

If you found a bug, please create an issue. Want to contribute? Yes, please! Create a pull request!