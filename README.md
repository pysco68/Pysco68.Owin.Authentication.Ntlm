# Pysco68.Owin.Authentication.NTLM

A passive NTLM autentication middleware for OWIN. This middleware enables you to use NTLM authentication independently of IIS or HTTPListener. Additionally it integrates easily with ASP.NET Identity 2.0. Being a passive middleware, it will enable you to use local application accounts with Windows Authentication as yet anoter mean of authentication!

## Installation

You can either clone this repository and include the project in your sources or install the nuget package using:

```
Install-Package Pysco68.Owin.Authentication.Ntlm 
```

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

> Note: you can provide a path to the `IOwinRequest.IsNtlmAuthenticationCallback(PathString redirectPath)` extension method. This is useful if the effective callback path is different from `NtlmAuthenticationOptions.DefaultRedirectPath` (for example if you specified something different in the setup or if you use the middleware in a virtual directory: see #7)

If you need to have detailled control about who logs into your application (say based on windows domain groups) you can pass a filter expression to the middleware:
```C#
// Enable NTLM authentication
app.UseNtlmAuthentication(new NtlmAuthenticationOptions() 
{
	Filter = (windowsIdentity, request) => 
		windowsIdentity.UserName.StartsWith("FOOBAR\\")	// user belongs to the domain "FOOBAR"
});        
```

Additionally you may want to controll the creation of the authentication identity being created when the user is authenticating. You can provide your own callback for `OnCreateIdentity` which takes the user's windows identity and the authentication options an must provide a `ClaimsIdentity`:

```C#
// Enable NTLM authentication
app.UseNtlmAuthentication(new NtlmAuthenticationOptions() 
{
	OnCreateIdentity  = (windowsIdentity, options, request) => 
	{
		// If the name is something like DOMAIN\username then
  		// grab the name part (and what if it looks like username@domain?)
        var parts = state.WindowsIdentity.Name.Split(new[] { '\\' }, 2);
        string shortName = parts.Length == 1 ? parts[0] : parts[parts.Length - 1];

        // we need to create a new identity using the sign in type that 
        // the cookie authentication is listening for
        var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);

        identity.AddClaims(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, state.WindowsIdentity.User.Value, null,
                Options.AuthenticationType),
            new Claim(ClaimTypes.Name, shortName),
            new Claim(ClaimTypes.Sid, state.WindowsIdentity.User.Value)
        });                              


		return identity;
	}
});        
```

## Kudos

Big thanks to Alexey Shytikov (@shytikov) and his Nancy.Authentication.Ntlm (https://github.com/toolchain/Nancy.Authentication.Ntlm) implementation of Ntlm for Nancy. 
It was a huge help!

Thanks to the contributors:

* Brannon King (@BrannonKing) for the `Filter` callback
* Martin Thwaites (@martinjt) for the `OnCreateIdentity` callback

## Help / Contribution

If you found a bug, please create an issue. Want to contribute? Yes, please! Create a pull request!
