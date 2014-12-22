namespace Pysco68.Owin.Authentication.Ntlm
{
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using System.Threading.Tasks;

    class NtlmAuthenticationHandler : AuthenticationHandler<NtlmAuthenticationOptions>
    {
        private readonly ILogger logger;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        public NtlmAuthenticationHandler(ILogger logger)
        {
            this.logger = logger;
        }


        /// <summary>
        /// Authenticate the request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // DUMMY
            await Task.Delay(0);
            return new AuthenticationTicket(null, null);

            // TODO:
            // implement the actual NTLM roundtrips in here!
        }

        /// <summary>
        /// Apply the first authorization step
        /// </summary>
        /// <returns></returns>
        protected override Task ApplyResponseChallengeAsync()
        {
            // only act on unauthorized responses
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                // this migth be our chance to request NTLM authentication!
                if (challenge != null)
                {
                    var state = challenge.Properties;

                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = Request.Uri.ToString();
                    }

                    var stateString = Options.StateDataFormat.Protect(state);
                    // TODO: add some cache to store a state in

                    // redirect to trigger trigger NTLM authentication
                    Response.Redirect(WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateString));
                }
            }

            return Task.Delay(0);
        }

        /// <summary>
        /// This is always invoked on each request. For passive middleware, only do anything if this is
        /// for our callback path when the user is redirected back from the authentication provider.
        /// </summary>
        /// <returns></returns>
        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync();
                if (ticket != null && ticket.Identity != null)
                {
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
                    Response.Redirect(ticket.Properties.RedirectUri);

                    // Prevent further processing by the owin pipeline.
                    return true;
                }
            }

            // Let the rest of the pipeline run.
            return false;
        }
    }
}
