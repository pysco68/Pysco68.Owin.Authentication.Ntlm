# Pysco68.Owin.Authentication.NTLM

A passive NTLM autentication middleware for OWIN. This middleware enables you to use NTLM authentication independently of IIS or HTTPListener. Additionally it integrates easily with ASP.NET Identity 2.0. Being a passive middleware, it will enable you to use local application accounts with Windows Authentication as yet anoter mean of authentication!

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

As with any other passive middleware you must provide some point of entry in your application that will start the authentication. As an example you could add a route like this one to your `Accounts` controller:

```C#
[AllowAnonymous]
[Route("ntlmlogin")]
[HttpGet]
public IHttpActionResult Ntlmlogin(string redirectUrl)
{
    // create a login challenge if there's no user logged in!
    if (this.User == null)
    {
        var ap = new AuthenticationProperties()
        {
            RedirectUri = redirectUrl
        };

        var context = this.Request.GetContext();
        context.Authentication.Challenge(ap, NtlmAuthenticationDefaults.AuthenticationType);
        return Unauthorized();
    }

    return Redirect(redirectUrl);
}
```

> Note: That route/action would be the place to sign in with (or to create) a local application account too.


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

Big thanks to Alexey Shytikov (@shytikov) and his Nancy.Authentication.Ntlm (https://github.com/toolchain/Nancy.Authentication.Ntlm) implementation of Ntlm for Nancy. 
It was a huge help!

## Help / Contribution

If you found a bug, please create an issue. Want to contribute? Yes, please! Create a pull request!