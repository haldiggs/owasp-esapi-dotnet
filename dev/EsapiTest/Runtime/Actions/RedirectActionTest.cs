using System;
using System.Web;
using EsapiTest.Surrogates;
using NUnit.Framework;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Runtime;
using Owasp.Esapi.Runtime.Actions;

namespace EsapiTest.Runtime.Actions
{
    [TestFixture]
    public class RedirectActionTest
    {
        [SetUp]
        public void TestInitialize()
        {
            Esapi.Reset();
            EsapiConfig.Reset();
        }

        [Test]
        public void Test_Execute()
        {
            IIntrusionDetector detector = Esapi.IntrusionDetector; 

            string url = Guid.NewGuid().ToString();
            RedirectAction action = new RedirectAction(url);
            
            // Set context
            MockHttpContext.InitializeCurrentContext();
            SurrogateWebPage page = new SurrogateWebPage();
            HttpContext.Current.Handler = page;

            // Block
            try {
                Assert.AreNotEqual(HttpContext.Current.Request.RawUrl, action.Url);
                action.Execute(ActionArgs.Empty);

                Assert.Fail("Request not terminated");
            }
            catch (Exception exp) {
                // FIXME : so far there is no other way to test the redirect except to check 
                // the stack of the exception. Ideally we should be able to mock the request
                // redirect itself
                Assert.IsTrue(exp.StackTrace.Contains("at System.Web.HttpResponse.Redirect(String url, Boolean endResponse)"));
            }
        }

        [Test]
        public void Test_Create()
        {
            string url = Guid.NewGuid().ToString();

            RedirectAction action = new RedirectAction(url);
            Assert.AreEqual(action.Url, url);
        }

        [Test]
        public void Test_InvalidCreate()
        {
            try {
                new RedirectAction(null);
                Assert.Fail("Null arg");
            }
            catch (ArgumentException) {
            }

            try {
                new RedirectAction(string.Empty);
                Assert.Fail("Empty arg");
            }
            catch (ArgumentException) {
            }
        }
    }
}
