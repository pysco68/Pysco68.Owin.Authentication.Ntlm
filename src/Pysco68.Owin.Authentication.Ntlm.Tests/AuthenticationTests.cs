using Microsoft.Owin.Hosting;
using Microsoft.Owin.Testing;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Pysco68.Owin.Authentication.Ntlm.Tests
{
    [TestFixture]
    public class AuthenticationTests
    {
        private IDisposable Server;
        private Uri BaseAddress;

        [TestFixtureSetUp]
        public void Init()
        {
            this.BaseAddress = new Uri("http://localhost:9999");
            this.Server = WebApp.Start<WebApplication>(new StartOptions()
            {
                Port = 9999
            });
        }

        [TestFixtureTearDown]
        public void Teardown()
        {
            this.Server.Dispose();
        }


        [Test]
        public async void LogInSuccessfully()
        {            
            var handler = new HttpClientHandler 
            { 
                AllowAutoRedirect = true, 
                Credentials = CredentialCache.DefaultNetworkCredentials
            };

            var client = new HttpClient(handler);            
            client.BaseAddress = this.BaseAddress;


            var response = await client.GetAsync("/api/test");
            var result = await response.Content.ReadAsAsync<string>();

            var currentUserName = Environment.UserName;

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, "Http status");
            Assert.AreEqual(currentUserName, result);            
        }

        [Test]
        public async void LogInFail()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true
            };

            var client = new HttpClient(handler);
            client.BaseAddress = this.BaseAddress;

            var response = await client.GetAsync("/api/test");
            var result = await response.Content.ReadAsAsync<string>();

            var currentUserName = Environment.UserName;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, "Http status");
            Assert.AreEqual(currentUserName, result, "Username");
        }
    }
}
