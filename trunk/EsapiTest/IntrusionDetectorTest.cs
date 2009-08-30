using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Configuration;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for IntrusionDetector
    /// </summary>
    [TestClass]
    public class IntrusionDetectorTest
    {
        [TestInitialize]
        public void InitializeTests()
        {
            Esapi.Reset();
            EsapiConfig.Reset();
        }
                
        [TestMethod]
        public void Test_AddException()
        {
            Esapi.IntrusionDetector.AddException(new IntrusionException("user message", "log message"));
        }

        [TestMethod]
        public void Test_AddESAPIException()
        {
            EnterpriseSecurityException secExp = new EnterpriseSecurityException();
            Esapi.IntrusionDetector.AddException(secExp);
        }

        [TestMethod]
        public void Test_AddExceptionSecurityEvent()
        {
            string evtName = typeof(ArgumentException).FullName;

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "log" });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            ArgumentException arg = new ArgumentException();
            Esapi.IntrusionDetector.AddException(arg);
        }

        [TestMethod]
        public void Test_AddEvent()
        {
            string evtName = Guid.NewGuid().ToString();

            Esapi.IntrusionDetector.AddEvent(evtName);
        }

        [TestMethod]
        public void Test_AddThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "logout" });
            Esapi.IntrusionDetector.AddThreshold(threshold);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_AddNullThreshold()
        {
            Esapi.IntrusionDetector.AddThreshold(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddDuplicateThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "logout" });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            Threshold dup = new Threshold(evtName, 2, 2, null);
            Esapi.IntrusionDetector.AddThreshold(dup);
        }

        [TestMethod]
        public void Test_RemoveThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "logout" });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            Assert.IsTrue( Esapi.IntrusionDetector.RemoveThreshold(evtName));
        }

        [TestMethod]
        public void Test_IntrusionDetected()
        {
            string evtName = Guid.NewGuid().ToString();

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "log" });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            Esapi.IntrusionDetector.AddEvent(evtName);
        }
    }
}
