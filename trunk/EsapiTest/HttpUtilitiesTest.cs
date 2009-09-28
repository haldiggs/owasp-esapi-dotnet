using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web;
using EsapiTest.Surrogates;
using log4net.Appender;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.HttpUtilities;
using Owasp.Esapi.Interfaces;
using log4net;
using System.Security.Principal;

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

        [TestMethod]
        public void Test_LogHttpRequest()
        {
            // Force log initialization
            Logger logger = new Logger(typeof(HttpUtilitiesTest).ToString());

            // Reset current configuration
            LogManager.ResetConfiguration();

            // Redirect log output to strinb guilder
            StringBuilder sb = new StringBuilder();
            TextWriterAppender appender = new TextWriterAppender();
            appender.Writer = new StringWriter(sb);
            appender.Threshold = log4net.Core.Level.Debug;
            appender.Layout = new log4net.Layout.PatternLayout();
            appender.ActivateOptions();
            log4net.Config.BasicConfigurator.Configure(appender);
                                              
            // Initialize current request
            string userIdentity = Guid.NewGuid().ToString();
            MockHttpContext.InitializeCurrentContext();
            HttpContext.Current.User = new GenericPrincipal( new GenericIdentity(userIdentity), null);

            // Log and test
            Esapi.HttpUtilities.LogHttpRequest(HttpContext.Current.Request, Esapi.Logger, null);
            Assert.IsFalse( string.IsNullOrEmpty(sb.ToString()));
            Assert.IsTrue(sb.ToString().Contains(userIdentity));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_LogNullHttpRequest()
        {
            MockHttpContext.InitializeCurrentContext();
            Esapi.HttpUtilities.LogHttpRequest(null, Esapi.Logger, null);            
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_LogHttpRequestNullLogger()
        {
            MockHttpContext.InitializeCurrentContext();
            Esapi.HttpUtilities.LogHttpRequest(HttpContext.Current.Request, null, null);            
        }
    }
}
