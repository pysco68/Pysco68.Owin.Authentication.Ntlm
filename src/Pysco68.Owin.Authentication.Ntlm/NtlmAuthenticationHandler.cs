
namespace Pysco68.Owin.Authentication.Ntlm
{
    using Microsoft.Owin;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Pysco68.Owin.Authentication.Ntlm.Security;
    using System;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using System.Security.Cryptography;

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
            // note: this is cheating for async...
            AuthenticationProperties properties = await Task.FromResult<AuthenticationProperties>(null);
            HandshakeState state = null;

            // retrieve the state Id
            var stateId = Request.Query["state"];


            if (stateId != null && this.Options.LoginStateCache.TryGet(stateId, out state))
            {
                // okay, we shall authenticate! For that we must
                // get the authorization header and extract the token
                var authorizationHeader = Request.Headers["Authorization"];

                byte[] token = null;
                if (!string.IsNullOrEmpty(authorizationHeader) && authorizationHeader.StartsWith("NTLM "))
                {
                    token = Convert.FromBase64String(authorizationHeader.Substring(5));
                }

                // First eight bytes are header containing NTLMSSP\0 signature
                // Next byte contains type of the message recieved.
                // No Token - it's the initial request. Add a authenticate header
                // Message Type 1 — is initial client's response to server's 401 Unauthorized error.
                // Message Type 2 — is the server's response to it. Contains random 8 bytes challenge.
                // Message Type 3 — is encrypted password hashes from client ready to server validation.
                if (token != null && token[8] == 1)
                {
                    // Message of type 1 was received
                    if (state.TryAcquireServerChallenge(ref token))
                    {
                        // send the type 2 message
                        var authorization = Convert.ToBase64String(token);
                        Response.Headers.Add("WWW-Authenticate", new[] {string.Concat("NTLM ", authorization)});
                        Response.StatusCode = 401;

                        // not sucessfull
                        return new AuthenticationTicket(null, properties);
                    }
                }
                else if (token != null && token[8] == 3)
                {
                    // message of type 3 was received
                    if (state.IsClientResponseValid(token))
                    {
                        // Authorization successful 
                        properties = state.AuthenticationProperties;

                        if (Options.Filter == null || Options.Filter.Invoke(state.WindowsIdentity, Request))
                        {
                            // If the name is something like DOMAIN\username then
                            // grab the name part (and what if it looks like username@domain?)
                            var parts = state.WindowsIdentity.Name.Split(new[] {'\\'}, 2);
                            string shortName = parts.Length == 1 ? parts[0] : parts[parts.Length - 1];

                            // we need to create a new identity using the sign in type that 
                            // the cookie authentication is listening for
                            var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);

                            identity.AddClaims(new[]
                            {
                                new Claim(ClaimTypes.NameIdentifier, state.WindowsIdentity.User.Value, null, Options.AuthenticationType),
                                new Claim(ClaimTypes.Name, shortName),
                                new Claim(ClaimTypes.Sid, state.WindowsIdentity.User.Value),
                                new Claim(ClaimTypes.AuthenticationMethod, NtlmAuthenticationDefaults.AuthenticationType)
                            });

                            // We don't need that state anymore
                            Options.LoginStateCache.TryRemove(stateId);

                            // create the authentication ticket
                            return new AuthenticationTicket(identity, properties);
                        }
                    }
                }

                // This code runs under following conditions:
                // - authentication failed (in either step: IsClientResponseValid() or TryAcquireServerChallenge())
                // - there's no token in the headers
                //
                // This means we've got to set the WWW-Authenticate header and return a 401
                Response.Headers.Add("WWW-Authenticate", new[] { "NTLM" });
                Response.StatusCode = 401;
            }

            return new AuthenticationTicket(null, properties);
        }

        /// <summary>
        /// Apply the first authorization step
        /// </summary>
        /// <returns></returns>
        protected override Task ApplyResponseChallengeAsync()
        {
            // only act on unauthorized responses
            if (Response.StatusCode == 401 && Response.Headers.ContainsKey("WWW-Authenticate") == false)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                // this migth be our chance to request NTLM authentication!
                if (challenge != null)
                {
                    var authProperties = challenge.Properties;

                    if (string.IsNullOrEmpty(authProperties.RedirectUri))
                    {
                        throw new ArgumentException("The authentication challenge's redirect URI can't be empty!");
                    }

                    // get a fairly "unique" string to use in the redirection URL
                    var protectedProperties = Options.StateDataFormat.Protect(authProperties);
                    var stateHash = CalculateMD5Hash(protectedProperties);

                    // create a new handshake state
                    var state = new HandshakeState()
                    {
                        AuthenticationProperties = authProperties
                    };

                    // and store it in the state cache
                    Options.LoginStateCache.Add(stateHash, state);

                    // redirect to trigger trigger NTLM authentication
                    Response.Redirect(WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateHash));
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
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.PathBase.Add(Request.Path))
            {
                var ticket = await AuthenticateAsync();
                if (ticket != null && ticket.Identity != null)
                {
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
                    Response.Redirect(ticket.Properties.RedirectUri);

                    // Prevent further processing by the owin pipeline.
                    return true;
                }
                if (Response.Headers.ContainsKey("WWW-Authenticate"))
                {
                    return true;
                }
            }

            // Let the rest of the pipeline run
            return false;
        }

        #region Helpers
        private static readonly MD5 _md5 = MD5.Create();
        public string CalculateMD5Hash(string input)
        {
            // step 1, calculate MD5 hash from input
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] hash = _md5.ComputeHash(inputBytes);

            // step 2, convert byte array to hex string
            var sb = new StringBuilder(hash.Length * 2);
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }
        #endregion
    }
}
