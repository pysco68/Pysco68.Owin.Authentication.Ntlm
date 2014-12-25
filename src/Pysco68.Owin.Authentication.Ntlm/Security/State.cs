namespace Pysco68.Owin.Authentication.Ntlm.Security
{
    using System;
    using Pysco68.Owin.Authentication.Ntlm.Native;

    /// <summary>
    /// A windows authentication session
    /// </summary>
    class State
    {
        public State()
        {
            this.Credentials = new SecurityHandle(0);
            this.Context = new SecurityHandle(0);
        }

        /// <summary>
        /// Credentials used to validate NTLM hashes
        /// </summary>
        private SecurityHandle Credentials;

        /// <summary>
        /// Context will be used to validate HTLM hashes
        /// </summary>
        private SecurityHandle Context;


        /// <summary>
        /// Try to acquire the server challenge for this state
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public bool TryAcquireServerChallenge(ref byte[] message)
        {
            SecurityBufferDesciption clientToken = new SecurityBufferDesciption(message);
            SecurityBufferDesciption serverToken = new SecurityBufferDesciption(Common.MaximumTokenSize);

            try
            {
                int result;
                var lifetime = new SecurityInteger(0);

                result = Interop.AcquireCredentialsHandle(
                    null,
                    "NTLM",
                    Common.SecurityCredentialsInbound,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    ref this.Credentials,
                    ref lifetime);

                if (result != Common.SuccessfulResult)
                {
                    // Credentials acquire operation failed.
                    return false;
                }

                uint contextAttributes;

                result = Interop.AcceptSecurityContext(
                    ref this.Credentials,                       // [in] handle to the credentials
                    IntPtr.Zero,                                // [in/out] handle of partially formed context.  Always NULL the first time through
                    ref clientToken,                            // [in] pointer to the input buffers
                    Common.StandardContextAttributes,           // [in] required context attributes
                    Common.SecurityNativeDataRepresentation,    // [in] data representation on the target
                    out this.Context,                           // [in/out] receives the new context handle    
                    out serverToken,                            // [in/out] pointer to the output buffers
                    out contextAttributes,                      // [out] receives the context attributes        
                    out lifetime);                              // [out] receives the life span of the security context

                if (result != Common.IntermediateResult)
                {
                    // Client challenge issue operation failed.
                    return false;
                }
            }
            finally
            {
                message = serverToken.GetBytes();
                clientToken.Dispose();
                serverToken.Dispose();
            }

            return true;
        }

        /// <summary>
        /// Validate the client response and fill the indentity of the token
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public bool IsClientResponseValid(byte[] message)
        {
            throw new NotImplementedException();
        }
    }
}
