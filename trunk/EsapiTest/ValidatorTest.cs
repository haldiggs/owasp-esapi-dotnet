using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Interfaces;
using Rhino.Mocks;
using Owasp.Esapi.ValidationRules;
using Owasp.Esapi.Configuration;
using Rhino.Mocks.Constraints;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for ValidatorTest
    /// </summary>
    [TestClass]
    public class ValidatorTest
    {
        [TestInitialize]
        public void InitializeTest()
        {
            Esapi.Reset();
            EsapiConfig.Reset();

            ForwardValidator.DefaultValidator = null;
        }

        [TestMethod]
        public void Test_CreditCardValidator()
        {
            		
		    IValidator validator = Esapi.Validator;
		    Assert.IsTrue(validator.IsValid(BuiltinValidationRules.CreditCard, "1234 9876 0000 0008"));
		    Assert.IsTrue(validator.IsValid(BuiltinValidationRules.CreditCard, "1234987600000008"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.CreditCard, "Garbage"));
		    Assert.IsFalse(validator.IsValid(BuiltinValidationRules.CreditCard, "12349876000000082"));
		    Assert.IsFalse(validator.IsValid(BuiltinValidationRules.CreditCard, "4417 1234 5678 9112"));
        }

        /// <summary> Test of IsValidDouble method, of class Owasp.Esapi.Validator.</summary>
        [TestMethod]
        public void Test_IsValidDouble()
        {
            System.Console.Out.WriteLine("IsValidNumber");
            IValidator validator = Esapi.Validator;
            //testing negative range
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "-4"));
            
            //testing empty string
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, ""));
            //testing non-integers
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "4.3214"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "-1.65"));
            //other testing
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "4"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "400"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "400000000"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "alsdkf"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "--10"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "14.1414234x"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "Infinity"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "-Infinity"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "NaN"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "-NaN"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, "+NaN"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "1e-6"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Double, "-1e-6"));

            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, string.Empty));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Double, null));
        }

        // <summary> Test of IsValidInteger method, of class Owasp.Esapi.Validator.</summary>
        public void Test_IsValidInteger()
        {
            IValidator validator = Esapi.Validator;
            //testing negative range
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "-4"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Integer, "-4"));
            //testing null value
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, null));
            //testing empty string
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, ""));
            //testing non-integers
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "4.3214"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "-1.65"));
            //other testing
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Integer, "4"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Integer, "400"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Integer, "400000000"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "4000000000000"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "alsdkf"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "--10"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "14.1414234x"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "Infinity"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "-Infinity"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "NaN"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "-NaN"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "+NaN"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "1e-6"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, "-1e-6"));

            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, string.Empty));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Integer, null));
        }

        /// <summary> Test of GetValidDate method, of class Owasp.Esapi.Validator.</summary>
        [TestMethod]
        public void Test_GetValidDate()
        {            
            IValidator validator = Esapi.Validator;
                        
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Date, "June 23, 1967"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Date, "Jun 23, 1967"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Date, "June 32, 1967"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Date, "June 32 1967"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Date, "June 32 abcd"));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Date, string.Empty));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Date, null));
        }

        
        /// <summary> Test of IsValidPrintable method, of class Owasp.Esapi.Validator.</summary>
        [TestMethod]
        public void Test_IsValidPrintable()
        {            
            IValidator validator = Esapi.Validator;
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Printable, "abcDEF"));
            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Printable, "!@#R()*$;><()"));

            char[] bytes = new char[] { (char)(0x60), (char)(0xFF), (char)(0x10), (char)(0x25) };
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Printable, new String(bytes)));

            Assert.IsTrue(validator.IsValid(BuiltinValidationRules.Printable, string.Empty));
            Assert.IsFalse(validator.IsValid(BuiltinValidationRules.Printable, null));
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

        /// <summary>
        /// Tests loading of configuration defined validator
        /// </summary>
        [TestMethod]
        public void Test_LoadCustom()
        {
            // Set new
            EsapiConfig.Instance.Validator.Type = typeof(ForwardValidator).AssemblyQualifiedName;

            IValidator validator = Esapi.Validator;
            Assert.IsTrue(validator.GetType().Equals(typeof(ForwardValidator)));           
        }

        /// <summary>
        /// Tests loading of assembly defined rules in a configuration defined
        /// validator
        /// </summary>
        [TestMethod]
        public void Test_LoadCustomAddinAssembly()
        {
            MockRepository mocks = new MockRepository();

            // Set new
            EsapiConfig.Instance.Validator.Type = typeof(ForwardValidator).AssemblyQualifiedName;

            // Set assemblies to load
            AddinAssemblyElement addinAssembly = new AddinAssemblyElement();
            addinAssembly.Name = typeof(Esapi).Assembly.FullName;
            EsapiConfig.Instance.Validator.Rules.Assemblies.Add(addinAssembly);

            // Set mock expectations
            IValidator mockValidator = mocks.StrictMock<IValidator>();

            // Load default
            Expect.Call(delegate { mockValidator.AddRule(BuiltinValidationRules.CreditCard, null); }).Constraints(Is.Equal(BuiltinValidationRules.CreditCard), Is.Anything());
            Expect.Call(delegate { mockValidator.AddRule(BuiltinValidationRules.Date, null); }).Constraints(Is.Equal(BuiltinValidationRules.Date), Is.Anything());
            Expect.Call(delegate { mockValidator.AddRule(BuiltinValidationRules.Double, null); }).Constraints(Is.Equal(BuiltinValidationRules.Double), Is.Anything());
            Expect.Call(delegate { mockValidator.AddRule(BuiltinValidationRules.Integer, null); }).Constraints(Is.Equal(BuiltinValidationRules.Integer), Is.Anything());
            Expect.Call(delegate { mockValidator.AddRule(BuiltinValidationRules.Printable, null); }).Constraints(Is.Equal(BuiltinValidationRules.Printable), Is.Anything());            
            mocks.ReplayAll();

            // Create and test
            ForwardValidator.DefaultValidator = mockValidator;
            IValidator validator = Esapi.Validator;

            Assert.IsTrue(validator.GetType().Equals(typeof(ForwardValidator)));
            mocks.VerifyAll();
        }

        /// <summary>
        /// Tests loading of configuration defined codecs 
        /// </summary>
        [TestMethod]
        public void Test_LoadCustomCodecs()
        {
            MockRepository mocks = new MockRepository();

            // Set new
            EsapiConfig.Instance.Validator.Type = typeof(ForwardValidator).AssemblyQualifiedName;

            // Set rules to load
            string[] ruleNames = new[] { Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), Guid.NewGuid().ToString() };
            foreach (string ruleName in ruleNames) {
                ValidationRuleElement ruleElement = new ValidationRuleElement();
                ruleElement.Name = ruleName;
                ruleElement.Type = typeof(ForwardValidationRule).AssemblyQualifiedName;

                EsapiConfig.Instance.Validator.Rules.Add(ruleElement);
            }

            // Set mock expectations
            IValidator mockValidator = mocks.StrictMock<IValidator>();

            // Custom rules are loaded and are of proper type
            foreach (string ruleName in ruleNames) {
                Expect.Call(delegate { mockValidator.AddRule(ruleName, null); }).Constraints(Is.Equal(ruleName), Is.TypeOf<ForwardValidationRule>());
            }
            mocks.ReplayAll();

            // Create and test
            ForwardValidator.DefaultValidator = mockValidator;
            IValidator validator = Esapi.Validator;

            Assert.IsTrue(validator.GetType().Equals(typeof(ForwardValidator)));
            mocks.VerifyAll();
        }
    }
}
