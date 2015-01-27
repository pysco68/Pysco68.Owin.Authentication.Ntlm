using Owin;
using Microsoft.Owin.Extensions;
using System;
using Microsoft.Owin;

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

        /// <summary>
        /// Check if the present request is actually a callpack path for the NTLM authentication middleware
        /// </summary>
        /// <remarks>
        /// If you didn't use the default redirection path in the configuration of the NTLM authentication 
        /// middleware you must supply the same path to this function. See overloads of this method.
        /// </remarks>
        /// <param name="request"></param>
        /// <returns>True if the request path is the callback path, false otherwise</returns>
        public static bool IsNtlmAuthenticationCallback(
            this IOwinRequest request)
        {
            return request.IsNtlmAuthenticationCallback(NtlmAuthenticationOptions.DefaultRedirectPath);
        }

        /// <summary>
        /// Check if the present request is actually a callpack path for the NTLM authentication middleware
        /// </summary>
        /// <param name="request"></param>
        /// <param name="redirectPath">The path to check against</param>
        /// <returns>True if the request path matches the callback path, false otherwise</returns>
        public static bool IsNtlmAuthenticationCallback(
            this IOwinRequest request, 
            PathString redirectPath)
        {
            return (request.PathBase.Add(request.Path) == redirectPath);
        }
    }
}
