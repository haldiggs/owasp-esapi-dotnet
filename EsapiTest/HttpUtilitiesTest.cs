using System;
using System.Web;
using EsapiTest.Surrogates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Interfaces;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for HttpUtilitiesTest
    /// </summary>
    [TestClass]
    public class HttpUtilitiesTest
    {
        [TestInitialize]
        public void TestInitialize()
        {
            Esapi.Reset();
            EsapiConfig.Reset();
        }

        [TestMethod]
        public void Test_AddCsrfToken()
        {
            MockHttpContext.InitializeCurrentContext();

            SurrogateWebPage page = new SurrogateWebPage();
            HttpContext.Current.Handler = page;

            Esapi.HttpUtilities.AddCsrfToken();
            Assert.AreEqual(page.ViewStateUserKey, HttpContext.Current.Session.SessionID);
        }

        [TestMethod]
        public void Test_AddCsrfTokenHref()
        {
            MockHttpContext.InitializeCurrentContext();

            string href = "http://localhost/somepage.aspx";

            Uri csrfUri = new Uri(Esapi.HttpUtilities.AddCsrfToken(href));
            Assert.IsTrue(csrfUri.Query.Contains(HttpUtilities.CSRF_TOKEN_NAME));
        }

        [TestMethod]
        public void Test_LoadCustom()
        {
            EsapiConfig.Instance.HttpUtilities.Type = typeof(SurrogateHttpUtilities).AssemblyQualifiedName;

            IHttpUtilities utilities = Esapi.HttpUtilities;
            Assert.AreEqual(utilities.GetType(), typeof(SurrogateHttpUtilities));
        }
    }
}
