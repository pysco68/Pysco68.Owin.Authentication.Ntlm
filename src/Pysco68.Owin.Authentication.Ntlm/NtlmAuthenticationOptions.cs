using System.Security.Principal;

namespace Pysco68.Owin.Authentication.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Pysco68.Owin.Authentication.Ntlm.Security;

    public class NtlmAuthenticationOptions : AuthenticationOptions
    {
        #region Internal fields
        /// <summary>
        /// The default redirection path used by the NTLM authentication middleware of
        /// the full roundtrip / handshakes
        /// </summary>
        internal static readonly PathString DefaultRedirectPath = new PathString("/authentication/ntlm-signin");

        /// <summary>
        /// Secured store for state data
        /// </summary>
        internal ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        
        /// <summary>
        /// Store states for the login attempts
        /// </summary>
        internal StateCache LoginStateCache { get; set; }
        #endregion

        /// <summary>
        /// Number of minutes a login can take (defaults to 2 minutes)
        /// </summary>
        public int LoginStateExpirationTime
        {
            set { LoginStateCache.ExpirationTime = value; }
            get { return LoginStateCache.ExpirationTime; }
        }

        /// <summary>
        /// The authentication type used for sign in
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// The callback string used for the NTLM authentication roundtrips, 
        /// defaults to "/authentication/ntlm-signin"
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// If this is set, it must return true to authenticate the user.
        /// It can be used to filter out users according to separate criteria.
        /// </summary>
        /// <remarks>
        /// Note that the Windows identity will be disposed shortly after this function has returned
        /// </remarks>
        public Func<WindowsIdentity, IOwinRequest, bool> Filter { get; set; }

        /// <summary>
        /// Creates an instance of Ntlm authentication options with default values.
        /// </summary>
        public NtlmAuthenticationOptions()
            : base(NtlmAuthenticationDefaults.AuthenticationType)
        {
            this.AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive;
            this.CallbackPath = NtlmAuthenticationOptions.DefaultRedirectPath;
            this.LoginStateCache = new StateCache("NtlmAuthenticationStateCache");
            this.LoginStateExpirationTime = 2;
        }
    }

    public static class NtlmAuthenticationDefaults
    {
        public const string AuthenticationType = "Ntlm";
    }
}
