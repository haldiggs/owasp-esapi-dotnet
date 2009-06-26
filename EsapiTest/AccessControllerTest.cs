using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for AccessControllerTest
    /// </summary>
    [TestClass]
    public class AccessControllerTest
    {
        public AccessControllerTest()
        {
            
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        [TestMethod]
        public void Test_AccessControllerAddRule()
        {
            Esapi.AccessController.AddRule("test", "test", "test");
            Assert.IsTrue(Esapi.AccessController.IsAuthorized("test", "test", "test"));
        }

        [TestMethod]
        public void Test_AccessControllerRemoveRule()
        {
            Esapi.AccessController.AddRule("test", "test", "test");
            Esapi.AccessController.RemoveRule("test", "test", "test");
            Assert.IsFalse(Esapi.AccessController.IsAuthorized("test", "test", "test"));
        }
    }
}
