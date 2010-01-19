using System;
using EsapiTest.Surrogates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Runtime;
using Owasp.Esapi.Runtime.Actions;
using Rhino.Mocks;

namespace EsapiTest.InstrusionDetector
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

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "log" });
            detector.AddThreshold(threshold);

            ArgumentException arg = new ArgumentException();
            detector.AddException(arg);
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

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "logout" });
            detector.AddThreshold(threshold);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddThresholdMissingAction()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { Guid.NewGuid().ToString() });
            detector.AddThreshold(threshold);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_AddNullThreshold()
        {
            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            detector.AddThreshold(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddDuplicateThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.FormsAuthenticationLogout });
            detector.AddThreshold(threshold);

            Threshold dup = new Threshold(evtName, 2, 2, null);
            detector.AddThreshold(dup);
        }

        [TestMethod]
        public void Test_RemoveThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "logout" });
            detector.AddThreshold(threshold);

            Assert.IsTrue( detector.RemoveThreshold(evtName));
        }

        [TestMethod]
        public void Test_IntrusionDetected()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "log"});
            detector.AddThreshold(threshold);

            Esapi.IntrusionDetector.AddEvent(evtName);
        }

        /// <summary>
        /// Test loading of a custom intrusion detector
        /// </summary>
        [TestMethod]
        public void Test_LoadCustom()
        {
            // Set new 
            EsapiConfig.Instance.IntrusionDetector.Type = typeof(SurrogateIntrusionDetector).AssemblyQualifiedName;

            IIntrusionDetector detector = Esapi.IntrusionDetector;
            Assert.IsTrue(detector.GetType().Equals(typeof(SurrogateIntrusionDetector)));
        }
    }
}
