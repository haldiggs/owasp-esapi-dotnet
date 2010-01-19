using System;
using System.Web;
using EsapiTest.Surrogates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Runtime;
using Owasp.Esapi.Runtime.Actions;

namespace EsapiTest.Runtime.Actions
{
    /// <summary>
    /// Summary description for BlockActionTest
    /// </summary>
    [TestClass]
    public class BlockActionTest
    {
        [TestInitialize]
        public void TestInitialize()
        {
            Esapi.Reset();
            EsapiConfig.Reset();
        }

        [TestMethod]
        public void Test_Execute()
        {
            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            // Should be loaded by default
            BlockAction action = new BlockAction();

            // Set context
            MockHttpContext.InitializeCurrentContext();
            SurrogateWebPage page = new SurrogateWebPage();
            HttpContext.Current.Handler = page;

            // Block
            Assert.AreNotEqual(HttpContext.Current.Response.StatusCode, action.StatusCode);
            
            action.Execute(ActionArgs.Empty);
            Assert.AreEqual(HttpContext.Current.Response.StatusCode, action.StatusCode);
        }

        [TestMethod]
        public void Test_SetStatusCode()
        {
            int statusCode = (new Random((int)DateTime.Now.Ticks)).Next();
            
            BlockAction action = new BlockAction();
            
            Assert.AreNotEqual(action.StatusCode, statusCode);
            action.StatusCode = statusCode;
            Assert.AreEqual(action.StatusCode, statusCode);
        }
    }
}
