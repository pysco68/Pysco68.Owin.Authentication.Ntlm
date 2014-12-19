using Owin;
using Microsoft.Owin.Extensions;
using System;

namespace Pysco68.Owin.Authentication.Ntlm
{
    public static class NtlmAuthenticationExtensions
    {
        /// <summary>
        /// Enable using Ntlm authentication
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static IAppBuilder UseNtlmAuthentication(this IAppBuilder app, NtlmAuthenticationOptions options = null)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            app.Use(typeof(NtlmAuthenticationMiddleware), app, options != null ? options : new NtlmAuthenticationOptions());
            app.UseStageMarker(PipelineStage.Authenticate);

            return app;
        }
    }
}
