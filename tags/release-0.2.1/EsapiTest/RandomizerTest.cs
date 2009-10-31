using System;
using System.Collections;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Interfaces;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for Randomizer
    /// </summary>
    [TestClass]
    public class RandomizerTest
    {
        public RandomizerTest()
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
        /// <summary> Test of GetRandomString method, of class Owasp.Esapi.Randomizer.</summary>
        [TestMethod]
        public void Test_GetRandomString()
        {
            System.Console.Out.WriteLine("GetRandomString");
            int length = 20;
            IRandomizer randomizer = Esapi.Randomizer;
            for (int i = 0; i < 100; i++)
            {
                string result = randomizer.GetRandomString(length, Owasp.Esapi.CharSetValues.Alphanumerics);
                Assert.AreEqual(length, result.Length);
            }
        }

        /// <summary> Test of GetRandomInteger method, of class Owasp.Esapi.Randomizer.</summary>
        [TestMethod]
        public void Test_GetRandomInteger()
        {
            System.Console.Out.WriteLine("GetRandomInteger");
            int min = Int32.MinValue;
            int max = Int32.MaxValue;
            IRandomizer randomizer = Esapi.Randomizer;
            int minResult = (max - min) / 2;
            int maxResult = (max - min) / 2;
            for (int i = 0; i < 100; i++)
            {
                int result = randomizer.GetRandomInteger(min, max);
                if (result < minResult)
                    minResult = result;
                if (result > maxResult)
                    maxResult = result;
            }
            Assert.AreEqual(true, (minResult >= min && maxResult <= max));
        }

        /// <summary> Test of GetRandomDouble method, of class Owasp.Esapi.Randomizer.</summary>
        [TestMethod]
        public void Test_GetRandomDouble()
        {
            System.Console.Out.WriteLine("GetRandomDouble");
            double min = -20.5234F;
            double max = 100.12124F;
            IRandomizer randomizer = Esapi.Randomizer;
            double minResult = (max - min) / 2;
            double maxResult = (max - min) / 2;
            for (int i = 0; i < 100; i++)
            {
                double result = randomizer.GetRandomDouble(min, max);
                if (result < minResult)
                    minResult = result;
                if (result > maxResult)
                    maxResult = result;
            }
            Assert.AreEqual(true, (minResult >= min && maxResult < max));
        }


        /// <summary> Test of GetRandomGUID method, of class Owasp.Esapi.Randomizer.</summary>
        [TestMethod]
        public void Test_GetRandomGUID()
        {
            System.Console.Out.WriteLine("GetRandomGUID");
            IRandomizer randomizer = Esapi.Randomizer;
            ArrayList list = new ArrayList();
            for (int i = 0; i < 100; i++)
            {
                string guid = randomizer.GetRandomGUID().ToString();
                if (list.Contains(guid))
                    Assert.Fail();
                list.Add(guid);
            }
        }

    }
}
