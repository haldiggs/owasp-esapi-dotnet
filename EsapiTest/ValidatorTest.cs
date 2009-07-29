using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Interfaces;
using Rhino.Mocks;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for ValidatorTest
    /// </summary>
    [TestClass]
    public class ValidatorTest
    {
        public ValidatorTest()
        {
            //
            // TODO: Add constructor logic here
            //
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
        public void Test_CreditCardValidator()
        {
            		
		    IValidator validator = Esapi.Validator;
		    Assert.IsTrue(validator.IsValid(Validator.CREDIT_CARD, "1234 9876 0000 0008"));
		    Assert.IsTrue(validator.IsValid(Validator.CREDIT_CARD, "1234987600000008"));
            Assert.IsFalse(validator.IsValid(Validator.CREDIT_CARD, "Garbage"));
		    Assert.IsFalse(validator.IsValid(Validator.CREDIT_CARD, "12349876000000082"));
		    Assert.IsFalse(validator.IsValid(Validator.CREDIT_CARD, "4417 1234 5678 9112"));
        }

        /// <summary> Test of IsValidDouble method, of class Owasp.Esapi.Validator.</summary>
        [TestMethod]
        public void Test_IsValidDouble()
        {
            System.Console.Out.WriteLine("IsValidNumber");
            IValidator validator = Esapi.Validator;
            //testing negative range
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "-4"));
            
            //testing empty string
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, ""));
            //testing non-integers
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "4.3214"));
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "-1.65"));
            //other testing
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "4"));
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "400"));
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "400000000"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "alsdkf"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "--10"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "14.1414234x"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "Infinity"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "-Infinity"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "NaN"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "-NaN"));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, "+NaN"));
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "1e-6"));
            Assert.IsTrue(validator.IsValid(Validator.DOUBLE, "-1e-6"));

            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, string.Empty));
            Assert.IsFalse(validator.IsValid(Validator.DOUBLE, null));
        }

        // <summary> Test of IsValidInteger method, of class Owasp.Esapi.Validator.</summary>
        public void Test_IsValidInteger()
        {
            IValidator validator = Esapi.Validator;
            //testing negative range
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "-4"));
            Assert.IsTrue(validator.IsValid(Validator.INTEGER, "-4"));
            //testing null value
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, null));
            //testing empty string
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, ""));
            //testing non-integers
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "4.3214"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "-1.65"));
            //other testing
            Assert.IsTrue(validator.IsValid(Validator.INTEGER, "4"));
            Assert.IsTrue(validator.IsValid(Validator.INTEGER, "400"));
            Assert.IsTrue(validator.IsValid(Validator.INTEGER, "400000000"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "4000000000000"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "alsdkf"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "--10"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "14.1414234x"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "Infinity"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "-Infinity"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "NaN"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "-NaN"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "+NaN"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "1e-6"));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, "-1e-6"));

            Assert.IsFalse(validator.IsValid(Validator.INTEGER, string.Empty));
            Assert.IsFalse(validator.IsValid(Validator.INTEGER, null));
        }

        /// <summary> Test of GetValidDate method, of class Owasp.Esapi.Validator.</summary>
        [TestMethod]
        public void Test_GetValidDate()
        {            
            IValidator validator = Esapi.Validator;
                        
            Assert.IsTrue(validator.IsValid(Validator.DATE, "June 23, 1967"));
            Assert.IsTrue(validator.IsValid(Validator.DATE, "Jun 23, 1967"));
            Assert.IsFalse(validator.IsValid(Validator.DATE, "June 32, 1967"));
            Assert.IsFalse(validator.IsValid(Validator.DATE, "June 32 1967"));
            Assert.IsFalse(validator.IsValid(Validator.DATE, "June 32 abcd"));
            Assert.IsFalse(validator.IsValid(Validator.DATE, string.Empty));
            Assert.IsFalse(validator.IsValid(Validator.DATE, null));
        }

        
        /// <summary> Test of IsValidPrintable method, of class Owasp.Esapi.Validator.</summary>
        [TestMethod]
        public void Test_IsValidPrintable()
        {            
            IValidator validator = Esapi.Validator;
            Assert.IsTrue(validator.IsValid(Validator.PRINTABLE, "abcDEF"));
            Assert.IsTrue(validator.IsValid(Validator.PRINTABLE, "!@#R()*$;><()"));

            char[] bytes = new char[] { (char)(0x60), (char)(0xFF), (char)(0x10), (char)(0x25) };
            Assert.IsFalse(validator.IsValid(Validator.PRINTABLE, new String(bytes)));

            Assert.IsTrue(validator.IsValid(Validator.PRINTABLE, string.Empty));
            Assert.IsFalse(validator.IsValid(Validator.PRINTABLE, null));
        }

        [TestMethod]
        public void Test_AddRule()
        {
            MockRepository mocks = new MockRepository();            
            IValidationRule rule = mocks.StrictMock<IValidationRule>();

            string test = Guid.NewGuid().ToString();

            Esapi.Validator.AddRule(test, rule);
            Assert.ReferenceEquals(Esapi.Validator.GetRule(test), rule);
        }

        [TestMethod]
        public void Test_RemoveRule()
        {
            MockRepository mocks = new MockRepository();
            IValidationRule rule = mocks.StrictMock<IValidationRule>();

            string test = Guid.NewGuid().ToString();

            Esapi.Validator.AddRule(test, rule);
            Assert.ReferenceEquals(Esapi.Validator.GetRule(test), rule);

            Esapi.Validator.RemoveRule(test);
            Assert.IsNull(Esapi.Validator.GetRule(test));
        }

        [TestMethod]
        public void Test_IsValid()
        {
            MockRepository mocks = new MockRepository();

            string test = Guid.NewGuid().ToString();

            IValidationRule rule = mocks.StrictMock<IValidationRule>();
            Expect.Call(rule.IsValid(test)).Return(true);
            mocks.ReplayAll();

            Esapi.Validator.AddRule(test, rule);
            Assert.ReferenceEquals(Esapi.Validator.GetRule(test), rule);

            Assert.IsTrue(Esapi.Validator.IsValid(test, test));
            mocks.VerifyAll();
        }
    }
}
