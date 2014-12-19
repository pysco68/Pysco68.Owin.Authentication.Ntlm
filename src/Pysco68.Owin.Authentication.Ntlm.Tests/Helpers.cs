using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Pysco68.Owin.Authentication.Ntlm.Tests
{
    static class Helpers
    {
        const string OWIN_CONTEXT = "MS_OwinContext";

        public static OwinContext GetContext(this HttpRequestMessage request)
        {
            if (request.Properties.ContainsKey(OWIN_CONTEXT))
            {
                OwinContext owinContext = request.Properties[OWIN_CONTEXT] as OwinContext;
                return owinContext;
            }

            return null;
        }
    }
}
