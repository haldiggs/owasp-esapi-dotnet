using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Rhino.Mocks;
using System.Security.Principal;
using System.Threading;
using EsapiTest.Surrogates;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for AccessControllerTest
    /// </summary>
    [TestClass]
    public class AccessControllerTest
    {
        private void SetCurrentUser(string subject)
        {
            Thread.CurrentPrincipal = !string.IsNullOrEmpty(subject) ? 
                                            new GenericPrincipal(new GenericIdentity(subject), null) : 
                                            null;
        }
    
        [TestInitialize]
        public void InitializeTests()
        {
            // Reset cached data
            Esapi.Reset();
            EsapiConfig.Reset();
            SetCurrentUser(null);
        }

        [TestMethod]
        public void Test_AccessControllerAddRule()
        {
            string test = Guid.NewGuid().ToString();

            Esapi.AccessController.AddRule(test, test, test);
            Assert.IsTrue(Esapi.AccessController.IsAuthorized(test, test, test));
        }

        [TestMethod]
        [ExpectedException(typeof(EnterpriseSecurityException))]
        public void Test_AddDuplicateRule()
        {
            string test = Guid.NewGuid().ToString();

            Esapi.AccessController.AddRule(test, test, test);
            Esapi.AccessController.AddRule(test, test, test);
        }

        [TestMethod]        
        public void Test_AddRuleNullParams()
        {
            try {
                Esapi.AccessController.AddRule(null, string.Empty, string.Empty);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }

            try {
                Esapi.AccessController.AddRule(string.Empty, null, string.Empty);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }

            try {
                Esapi.AccessController.AddRule(string.Empty, string.Empty, null);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]        
        public void Test_IsAuthorizedResource()
        {
            Guid    action = Guid.NewGuid(), resource = Guid.NewGuid();
            string  subject = Guid.NewGuid().ToString();

            SetCurrentUser(subject);
            
            // Allow action
            Esapi.AccessController.AddRule(subject, action, resource);

            // Verify current
            Assert.IsTrue(Esapi.AccessController.IsAuthorized(action, resource));

            Assert.IsFalse(Esapi.AccessController.IsAuthorized(action, Guid.NewGuid()));
        }

        [TestMethod]
        public void Test_IsAuthorizedSubject()
        {
            Guid action = Guid.NewGuid(), resource = Guid.NewGuid(), subject = Guid.NewGuid();

            Esapi.AccessController.AddRule(subject, action, resource);
            Assert.IsTrue(Esapi.AccessController.IsAuthorized(subject, action, resource));

            Assert.IsFalse(Esapi.AccessController.IsAuthorized(Guid.NewGuid(), action, resource));
        }

        [TestMethod]
        public void Test_IsAuthorizedNullParams()
        {
            try {
                Esapi.AccessController.IsAuthorized(null, string.Empty, string.Empty);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }

            try {
                Esapi.AccessController.IsAuthorized(string.Empty, null, string.Empty);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }

            try {
                Esapi.AccessController.IsAuthorized(string.Empty, string.Empty, null);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }
        }
                
        [TestMethod]
        public void Test_AccessControllerRemoveRule()
        {
            string test = Guid.NewGuid().ToString();

            Esapi.AccessController.AddRule(test, test, test);
            Esapi.AccessController.RemoveRule(test, test, test);
            Assert.IsFalse(Esapi.AccessController.IsAuthorized(test, test, test));
        }


        [TestMethod]
        [ExpectedException(typeof(EnterpriseSecurityException))]
        public void Test_RemoveRuleWrongSubject()
        {
            string test = Guid.NewGuid().ToString();

            Esapi.AccessController.AddRule(test, test, test);
            Esapi.AccessController.RemoveRule(string.Empty, test, test);
        }

        [TestMethod]
        [ExpectedException(typeof(EnterpriseSecurityException))]
        public void Test_RemoveRuleWrongAction()
        {
            string test = Guid.NewGuid().ToString();

            Esapi.AccessController.AddRule(test, test, test);
            Esapi.AccessController.RemoveRule(test, string.Empty, test);
        }

        [TestMethod]
        [ExpectedException(typeof(EnterpriseSecurityException))]
        public void Test_RemoveRuleWrongResource()
        {
            string test = Guid.NewGuid().ToString();

            Esapi.AccessController.AddRule(test, test, test);
            Esapi.AccessController.RemoveRule(test, test, string.Empty);
        }

        [TestMethod]
        public void Test_RemoveRuleNullParams()
        {
            try {
                Esapi.AccessController.RemoveRule(null, string.Empty, string.Empty);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }

            try {
                Esapi.AccessController.RemoveRule(string.Empty, null, string.Empty);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }

            try {
                Esapi.AccessController.RemoveRule(string.Empty, string.Empty, null);
                Assert.Fail();
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]
        public void Test_LoadCustom()
        {
            MockRepository mocks = new MockRepository();

            // Set new controller type
            EsapiConfig.Instance.AccessController.Type = typeof(SurrogateAccessController).AssemblyQualifiedName;

            // Get existing
            IAccessController accessController = Esapi.AccessController;
            Assert.IsTrue(accessController.GetType().Equals(typeof(SurrogateAccessController)));

            // Call some methods
            IAccessController mockController = mocks.StrictMock<IAccessController>();
            ((SurrogateAccessController)accessController).Impl = mockController;
                        
            Expect.Call(mockController.IsAuthorized(null, null)).Return(true);
            Expect.Call(mockController.IsAuthorized(null, null, null)).Return(false);
            mocks.ReplayAll();

            Assert.IsTrue(Esapi.AccessController.IsAuthorized(null, null));
            Assert.IsFalse(Esapi.AccessController.IsAuthorized(null, null, null));
            mocks.VerifyAll();
        }        
    }
}
