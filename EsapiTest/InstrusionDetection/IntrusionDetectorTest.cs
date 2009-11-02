using System;
using EsapiTest.Surrogates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.IntrusionDetection.Actions;
using Rhino.Mocks;
using Rhino.Mocks.Constraints;
using Owasp.Esapi.IntrusionDetection;

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

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.Log});
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

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.FormsAuthenticationLogout });
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

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.FormsAuthenticationLogout });
            detector.AddThreshold(threshold);

            Assert.IsTrue( detector.RemoveThreshold(evtName));
        }

        [TestMethod]
        public void Test_IntrusionDetected()
        {
            string evtName = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            Threshold threshold = new Threshold(evtName, 1, 1, new[] { BuiltinActions.Log });
            detector.AddThreshold(threshold);

            Esapi.IntrusionDetector.AddEvent(evtName);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddActionEmptyName()
        {
            MockRepository mocks = new MockRepository();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            detector.AddAction(null, mocks.StrictMock<IAction>());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_AddNullAction()
        {
            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            detector.AddAction(Guid.NewGuid().ToString(), null);
        }

        [TestMethod]
        public void Test_AddDuplicateAction()
        {
            MockRepository mocks = new MockRepository();

            string name = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            detector.AddAction(name, mocks.StrictMock<IAction>());

            try {
                detector.AddAction(name, mocks.StrictMock<IAction>());
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

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            detector.AddAction(name, mocks.StrictMock<IAction>());
            Assert.IsTrue(detector.RemoveAction(name));
        }

        [TestMethod]
        public void Test_GetAction()
        {
            MockRepository mocks = new MockRepository();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            // Get valid
            string name = Guid.NewGuid().ToString();
            detector.AddAction(name, mocks.StrictMock<IAction>());
            Assert.IsNotNull(detector.GetAction(name));

            // Get invalid
            Assert.IsNull(detector.GetAction(Guid.NewGuid().ToString()));
        }

        [TestMethod]
        public void Test_RemoveInvalidAction()
        {
            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            string name = Guid.NewGuid().ToString();
            Assert.IsFalse(detector.RemoveAction(name));
        }
        
        [TestMethod]
        public void Test_RemoveReferencedAction()
        {
            MockRepository mocks = new MockRepository();

            string name = Guid.NewGuid().ToString();

            IntrusionDetector detector = Esapi.IntrusionDetector as IntrusionDetector;
            Assert.IsNotNull(detector);

            detector.AddAction(name, mocks.StrictMock<IAction>());

            Threshold threshold = new Threshold(Guid.NewGuid().ToString(), 1, 1, new[] { name });
            detector.AddThreshold(threshold);

            try {
                detector.RemoveAction(name);
                Assert.Fail("Referenced action removed successfully");
            }
            catch (ArgumentException) {
            }
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

#if false
        /// <summary>
        /// Test loading of actions from a custom assembly
        /// </summary>
        [TestMethod]
        public void Test_LoadCustomActionAssembly()
        {
            MockRepository mocks = new MockRepository();

            // Set new
            EsapiConfig.Instance.IntrusionDetector.Type = typeof(IntrusionDetector).AssemblyQualifiedName;

            // Set assemblies to load
            AddinAssemblyCollection addinAssemblies = new AddinAssemblyCollection();
            EsapiConfig.Instance.IntrusionDetector.Actions.Assemblies = addinAssemblies;
            
            AddinAssemblyElement addinAssembly = new AddinAssemblyElement();
            addinAssembly.Name = typeof(Esapi).Assembly.FullName;
            EsapiConfig.Instance.IntrusionDetector.Actions.Assemblies.Add(addinAssembly);            

            // Set mock expectations
            IIntrusionDetector mockDetector = mocks.StrictMock<IIntrusionDetector>();

            // Load default
            Expect.Call(delegate { mockDetector.AddAction(BuiltinActions.Log, null); }).Constraints(Is.Equal(BuiltinActions.Log), Is.Anything());
            Expect.Call(delegate { mockDetector.AddAction(BuiltinActions.FormsAuthenticationLogout, null); }).Constraints(Is.Equal(BuiltinActions.FormsAuthenticationLogout), Is.Anything());
            Expect.Call(delegate { mockDetector.AddAction(BuiltinActions.MembershipDisable, null); }).Constraints(Is.Equal(BuiltinActions.MembershipDisable), Is.Anything());
            Expect.Call(delegate { mockDetector.AddAction(BuiltinActions.Block, null); }).Constraints(Is.Equal(BuiltinActions.Block), Is.Anything());
            mocks.ReplayAll();

            SurrogateIntrusionDetector.DefaultDetector = mockDetector;
            IIntrusionDetector detector = Esapi.IntrusionDetector;

            Assert.IsTrue(detector.GetType().Equals(typeof(SurrogateIntrusionDetector)));
            mocks.VerifyAll();
        }

        /// <summary>
        /// Load custom actions via configuration
        /// </summary>
        [TestMethod]
        public void Test_LoadCustomActions()
        {
            MockRepository mocks = new MockRepository();

            EsapiConfig.Instance.IntrusionDetector.Type = typeof(SurrogateIntrusionDetector).AssemblyQualifiedName;

            // Set actions to load
            EsapiConfig.Instance.IntrusionDetector.Actions = new ActionCollection();

            string[] actionNames = new[] { Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), Guid.NewGuid().ToString() };
            foreach (string actionName in actionNames) {
                ActionElement actionElement = new ActionElement();
                actionElement.Name = actionName;
                actionElement.Type = typeof(SurrogateAction).AssemblyQualifiedName;

                EsapiConfig.Instance.IntrusionDetector.Actions.Add(actionElement);
            }

            // Set mock expectations
            IIntrusionDetector mockDetector = mocks.StrictMock<IIntrusionDetector>();

            // Custom actions are loaded and are of proper type
            foreach (string actionName in actionNames) {
                Expect.Call(delegate { mockDetector.AddAction(actionName, null); }).Constraints(Is.Equal(actionName), Is.TypeOf<SurrogateAction>());
            }
            mocks.ReplayAll();

            // Create and test
            SurrogateIntrusionDetector.DefaultDetector = mockDetector;
            IIntrusionDetector detector = Esapi.IntrusionDetector;

            Assert.IsTrue(detector.GetType().Equals(typeof(SurrogateIntrusionDetector)));
            mocks.VerifyAll();
        }

        /// <summary>
        /// Test event threshold configurationa
        /// </summary>
        [TestMethod]
        public void Test_LoadCustomEventThreshold()
        {
            MockRepository mocks = new MockRepository();

            EsapiConfig.Instance.IntrusionDetector.Type = typeof(SurrogateIntrusionDetector).AssemblyQualifiedName;

            // Set actions
            AddinAssemblyElement addinAssembly = new AddinAssemblyElement();
            addinAssembly.Name = typeof(Esapi).Assembly.FullName;
            EsapiConfig.Instance.IntrusionDetector.Actions.Assemblies.Add(addinAssembly);            
            
            // Set thresholds
            ThresholdElement thresholdElement = new ThresholdElement() {
                                                    Actions = BuiltinActions.Log,
                                                    Count = 1,
                                                    Interval = 1,
                                                    Name = Guid.NewGuid().ToString()
                                                };
            EsapiConfig.Instance.IntrusionDetector.EventThresholds = new EventThresholdCollection();
            EsapiConfig.Instance.IntrusionDetector.EventThresholds.Add(thresholdElement);

            // Set mock expectations
            IIntrusionDetector mockDetector = mocks.StrictMock<IIntrusionDetector>();
            Expect.Call(delegate { mockDetector.AddAction(null, null); }).Constraints(Is.Anything(), Is.Anything()).Repeat.Any();
            Expect.Call(delegate { mockDetector.AddThreshold(null); }).Constraints(Is.Anything());
            mocks.ReplayAll();

            // Test
            SurrogateIntrusionDetector.DefaultDetector = mockDetector;
            IIntrusionDetector detector = Esapi.IntrusionDetector;

            Assert.IsTrue(detector.GetType().Equals(typeof(SurrogateIntrusionDetector)));
            mocks.VerifyAll();            
        }
#endif
    }
}
