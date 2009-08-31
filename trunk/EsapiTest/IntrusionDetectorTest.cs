using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.IntrusionDetection.Actions;
using Rhino.Mocks;
using Owasp.Esapi.Interfaces;
using EM = Owasp.Esapi.Resources.Errors;

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

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.Log});
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

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.FormsAuthenticationLogout });
            Esapi.IntrusionDetector.AddThreshold(threshold);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddThresholdMissingAction()
        {
            string evtName = Guid.NewGuid().ToString();

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { Guid.NewGuid().ToString() });
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

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.FormsAuthenticationLogout });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            Threshold dup = new Threshold(evtName, 2, 2, null);
            Esapi.IntrusionDetector.AddThreshold(dup);
        }

        [TestMethod]
        public void Test_RemoveThreshold()
        {
            string evtName = Guid.NewGuid().ToString();

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.FormsAuthenticationLogout });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            Assert.IsTrue( Esapi.IntrusionDetector.RemoveThreshold(evtName));
        }

        [TestMethod]
        public void Test_IntrusionDetected()
        {
            string evtName = Guid.NewGuid().ToString();

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.Log });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            Esapi.IntrusionDetector.AddEvent(evtName);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddActionEmptyName()
        {
            MockRepository mocks = new MockRepository();

            Esapi.IntrusionDetector.AddAction(null, mocks.StrictMock<IAction>());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_AddNullAction()
        {
            Esapi.IntrusionDetector.AddAction(Guid.NewGuid().ToString(), null);
        }

        [TestMethod]
        public void Test_AddDuplicateAction()
        {
            MockRepository mocks = new MockRepository();

            string name = Guid.NewGuid().ToString();

            Esapi.IntrusionDetector.AddAction(name, mocks.StrictMock<IAction>());

            try {
                Esapi.IntrusionDetector.AddAction(name, mocks.StrictMock<IAction>());
                Assert.Fail("Duplicated action added successfully");
            }
            catch (ArgumentException) {
            }
        }

        [TestMethod]
        public void Test_RemoveAction()
        {
            MockRepository mocks = new MockRepository();

            string name = Guid.NewGuid().ToString();

            Esapi.IntrusionDetector.AddAction(name, mocks.StrictMock<IAction>());
            Assert.IsTrue(Esapi.IntrusionDetector.RemoveAction(name));
        }

        [TestMethod]
        public void Test_RemoveInvalidAction()
        {
            string name = Guid.NewGuid().ToString();
            Assert.IsFalse(Esapi.IntrusionDetector.RemoveAction(name));
        }
        
        [TestMethod]
        public void Test_RemoveReferencedAction()
        {
            MockRepository mocks = new MockRepository();

            string name = Guid.NewGuid().ToString();

            Esapi.IntrusionDetector.AddAction(name, mocks.StrictMock<IAction>());

            Threshold threshold = new Threshold(Guid.NewGuid().ToString(), 1, 1, new[] { name });
            Esapi.IntrusionDetector.AddThreshold(threshold);

            try {
                Esapi.IntrusionDetector.RemoveAction(name);
                Assert.Fail("Referenced action removed successfully");
            }
            catch (ArgumentException) {
            }
        }
    }
}
