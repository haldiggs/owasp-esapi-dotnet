using System;
using System.Collections;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Errors;
namespace EsapiTest
{
    /// <summary>
    /// Summary description for AccessReferenceMapTest
    /// </summary>
    [TestClass]
    public class AccessReferenceMapTest
    {

        class Account
        {
            int Balance;
            string Name;            
            public Account(int balance, string name)
            {
                Name = name;
                Balance = balance;
            }
        }

        ArrayList accounts = null;
        AccessReferenceMap arm = null;
        Account account1 = null;
        Account account2 = null;
        Account account3 = null;

        public AccessReferenceMapTest()
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
         /// <summary>
         /// Set up an access reference map
         /// </summary>
         [TestInitialize()]
         public void MyTestInitialize() 
         {             
             account1 = new Account(1000, "test1");
             account2 = new Account(2000, "test2");
             account3 = new Account(3000, "test3");
             accounts = new ArrayList();
             accounts.Add(account1);
             accounts.Add(account2);
             accounts.Add(account3);
             arm = new AccessReferenceMap(accounts);
         }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        [TestMethod]
        public void Test_Update()
        {
            System.Console.Out.WriteLine("Update");
            // test to make sure update returns something
            arm.Update(accounts);
            Assert.IsNotNull(arm.GetIndirectReference(account1));

            // test to make sure update removes items that are no longer in the list
            accounts.Remove(account3);
            arm.Update(accounts);
            String indirect = arm.GetIndirectReference(account3);
            Assert.IsNull(indirect);            

            // test to make sure old indirect reference is maintained after an update
            arm.Update(accounts);
            String newIndirect = arm.GetIndirectReference(account3);
            Assert.AreEqual(indirect, newIndirect);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_UpdateNull()
        {
            arm.Update(null);
        }


        /// <summary> Test of GetDirectReferences method, of class Owasp.Esapi.AccessReferenceMap.</summary>        
        [TestMethod]
        public void Test_GetDirectReferences()
        {
            System.Console.Out.WriteLine("GetDirectReferences");
            IEnumerator enumerator = arm.GetDirectReferences().GetEnumerator();
            int index = 0;
            while (enumerator.MoveNext())
            {
                Account account = (Account)enumerator.Current;                
                Assert.IsTrue(accounts.Contains(account));
                index++;
            }
            Assert.AreEqual(accounts.Count, index);
        }



        /// <summary> Test of GetDirectRefrences method, of class Owasp.Esapi.AccessReferenceMap.</summary>        
        [TestMethod]
        public void Test_GetIndirectReferences()
        {
            System.Console.Out.WriteLine("GetIndirectreferences");
            IEnumerator enumerator = arm.GetIndirectReferences().GetEnumerator();
            int index = 0;
            while (enumerator.MoveNext())
            {
                String indirectReference = (string) enumerator.Current;
                Assert.IsNotNull(arm.GetDirectReference(indirectReference));
                index++;
            }
            Assert.AreEqual(accounts.Count, index);
        }


        /// <summary> Test of getIndirectReference method, of class
        /// Owasp.Esapi.AccessReferenceMap.
        /// </summary>        
        [TestMethod]
        public void Test_GetIndirectReference()
        {
            System.Console.Out.WriteLine("GetIndirectReference");
            string indirect = arm.GetIndirectReference(account1);
            Assert.AreNotEqual(indirect, account1);
            Assert.AreEqual(arm.GetDirectReference(indirect), account1);
        }

        /// <summary> Test of getDirectReference method, of class
        /// Owasp.Esapi.AccessReferenceMap.
        /// 
        /// </summary>
        /// <throws>  AccessControlException </throws>
        /// <summary>             the access control exception
        /// </summary>
        [ExpectedException(typeof(AccessControlException))]
        public void Test_GetDirectReference()
        {
            System.Console.Out.WriteLine("GetDirectReference");
            arm.GetDirectReference("invalid");            
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_GetDirectReferenceNull()
        {
            arm.GetDirectReference(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_GetIndirectReferenceNull()
        {
            arm.GetIndirectReference(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_AddDirectReferenceNull()
        {
            arm.AddDirectReference(null);
        }

        [TestMethod]
        public void Test_AddDirectReference()
        {
            Guid direct = Guid.NewGuid();

            string indirect = arm.AddDirectReference(direct);
            Assert.AreEqual(arm.GetDirectReference(indirect), direct);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_RemoveDirectReferenceNull()
        {
            arm.RemoveDirectReference(null);
        }

        [TestMethod]
        public void Test_RemoveDirectReference()
        {
            Guid direct = Guid.NewGuid();

            string indirect = arm.AddDirectReference(direct);
            Assert.AreEqual(direct, arm.GetDirectReference(indirect));

            Assert.AreEqual(indirect, arm.RemoveDirectReference(direct));
        }
    }
}
