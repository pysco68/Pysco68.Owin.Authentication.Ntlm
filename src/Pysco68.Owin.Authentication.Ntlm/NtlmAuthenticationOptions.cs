namespace Pysco68.Owin.Authentication.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    public class NtlmAuthenticationOptions : AuthenticationOptions
    {
        #region Internal fields
        /// <summary>
        /// Secured store for state data
        /// </summary>
        internal ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        #endregion

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
        /// Creates an instance of Ntlm authentication options with default values.
        /// </summary>
        public NtlmAuthenticationOptions()
            : base(NtlmAuthenticationDefaults.AuthenticationType)
        {
            this.AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive;
            this.CallbackPath = new PathString("/authentication/ntlm-signin");
        }
    }

    public static class NtlmAuthenticationDefaults
    {
        public const string AuthenticationType = "Ntlm";
    }
}
