namespace Pysco68.Owin.Authentication.Ntlm
{
    using Owin;
    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.DataHandler;
    using System;
    using System.Collections.Generic;
    using System.Linq;

    public class NtlmAuthenticationMiddleware : AuthenticationMiddleware<NtlmAuthenticationOptions>
    {
        private readonly ILogger logger;

        public NtlmAuthenticationMiddleware(
            OwinMiddleware next,
            global::Owin.IAppBuilder app,
            NtlmAuthenticationOptions options)
            : base(next, options)
        {
            this.logger = app.CreateLogger<AuthenticationHandler>();

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(NtlmAuthenticationMiddleware).FullName, options.AuthenticationType);
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }

        protected override AuthenticationHandler<NtlmAuthenticationOptions> CreateHandler()
        {
            return new NtlmAuthenticationHandler(logger);
        }
    } 
}
