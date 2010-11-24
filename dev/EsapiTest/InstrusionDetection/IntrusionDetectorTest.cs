using System;
using EsapiTest.Surrogates;
using NUnit.Framework;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Runtime.Actions;

namespace EsapiTest.InstrusionDetector
{
    /// <summary>
    /// Summary description for IntrusionDetector
    /// </summary>
    [TestFixture]
    public class IntrusionDetectorTest
    {
        [SetUp]
        public void InitializeTests()
        {
            Esapi.Reset();
            EsapiConfig.Reset();
        }
                
        [Test]
        public void Test_AddException()
        {
            Esapi.IntrusionDetector.AddException(new IntrusionException("user message", "log message"));
        }

        [Test]
        public void Test_AddESAPIException()
        {
            EnterpriseSecurityException secExp = new EnterpriseSecurityException();
            Esapi.IntrusionDetector.AddException(secExp);
        }

        [Test]
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

        [Test]
        public void Test_AddEvent()
        {
            string evtName = Guid.NewGuid().ToString();

            Esapi.IntrusionDetector.AddEvent(evtName);
        }

        [Test]
        public void Test_AddThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "logout" });
            detector.AddThreshold(threshold);
        }

        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddThresholdMissingAction()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { Guid.NewGuid().ToString() });
            detector.AddThreshold(threshold);
        }

        [Test]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_AddNullThreshold()
        {
            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            detector.AddThreshold(null);
        }

        [Test]
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

        [Test]
        public void Test_RemoveThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { "logout" });
            detector.AddThreshold(threshold);

            Assert.IsTrue( detector.RemoveThreshold(evtName));
        }

        [Test]
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
        [Test]
        public void Test_LoadCustom()
        {
            // Set new 
            EsapiConfig.Instance.IntrusionDetector.Type = typeof(SurrogateIntrusionDetector).AssemblyQualifiedName;

            IIntrusionDetector detector = Esapi.IntrusionDetector;
            Assert.IsTrue(detector.GetType().Equals(typeof(SurrogateIntrusionDetector)));
        }
    }
}
