using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System.Web.Http;

namespace Pysco68.Owin.Authentication.Ntlm.Tests
{
    class WebApplication
    {
        public void Configuration(IAppBuilder app)
        {
            // use default sign in with application cookies
            app.SetDefaultSignInAsAuthenticationType("ApplicationCookie");

            // set up the cookie aut
            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = "ApplicationCookie",
                LoginPath = new PathString("/api/account/ntlmlogin"),
                ReturnUrlParameter = "redirectUrl",
                Provider = new CookieAuthenticationProvider()
                {
                    OnApplyRedirect = ctx =>
                    {
                        if (!ctx.Request.IsNtlmAuthenticationCallback())
                        {
                            ctx.Response.Redirect(ctx.RedirectUri);
                        }
                    }
                }
            });

            // Enable NTLM authentication
            app.UseNtlmAuthentication();

            // configure web api
            var config = new HttpConfiguration();
            config.Routes.MapHttpRoute("DefaultApi", "api/{controller}/{id}", new { id = RouteParameter.Optional });

            app.UseWebApi(config);
        }
    }

    /// <summary>
    /// Test controller returning the username if authentication succeeds!
    /// </summary>
    [Authorize]
    public class TestController : ApiController
    {
        // GET /api/test
        public string Get()
        {
            if (User == null) return "Not authenticated!";

            return User.Identity.Name;
        }
    }

    [Authorize]
    [RoutePrefix("api/account")]
    public class AccountController : ApiController
    {
        public AccountController()
        {

        }

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
    }
}
