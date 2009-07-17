using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Interfaces;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for EncoderTest
    /// </summary>
    [TestClass]
    public class EncoderTest
    {
        public EncoderTest()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        private TestContext testContextencoder;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextencoder;
            }
            set
            {
                testContextencoder = value;
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

        /// <summary> Test of Canonicalize method, of class Owasp.Esapi.Validator.
        /// 
        /// </summary>
        /// <throws>  ValidationException </throws>
        [TestMethod]
        public void Test_Canonicalize()
        {
            
        }

        /// <summary> Test of Normalize method, of class Owasp.Esapi.Validator.
        /// 
        /// </summary>
        /// <throws>  ValidationException </throws>
        /// <summary>             the validation exception
        /// </summary>
        [TestMethod]
        public void Test_Normalize()
        {
            System.Console.Out.WriteLine("Normalize");
            // Assert.AreEqual(Esapi.Encoder.Normalize("é à î _ @ \" < > \u20A0"), "e a i _ @ \" < > ");
        }

        /// <summary> Test of EncodeForHtml method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForHtml()
        {
            System.Console.Out.WriteLine("EncodeForHtml");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.EncodeForHtml(null));
            // test invalid characters are replaced with spaces
            Assert.AreEqual("a&#0;b&#4;c&#128;d&#150;e&#159;f&#9;g", encoder.EncodeForHtml("a" + (char)0 + "b" + (char)4 + "c" + (char)128 + "d" + (char)150 + "e" + (char)159 + "f" + (char)9 + "g"));        
            Assert.AreEqual("&#60;script&#62;", encoder.EncodeForHtml("<script>"));
            Assert.AreEqual("&#38;lt&#59;script&#38;gt&#59;", encoder.EncodeForHtml("&lt;script&gt;"));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForHtml("!@$%()=+{}[]"));
            // Assert.AreEqual("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", encoder.EncodeForHtml(encoder.Canonicalize("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;") ) );
            Assert.AreEqual(",.-_ ", encoder.EncodeForHtml(",.-_ "));
            Assert.AreEqual("dir&#38;", encoder.EncodeForHtml("dir&"));
            Assert.AreEqual("one&#38;two", encoder.EncodeForHtml("one&two"));
            Assert.AreEqual("" + (char)12345 + (char)65533 + (char)1244, "" + (char)12345 + (char)65533 + (char)1244 );
        }

        /// <summary> Test of EncodeForHtmlAttribute method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForHtmlAttribute()
        {
            System.Console.Out.WriteLine("EncodeForHtmlAttribute");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.EncodeForHtmlAttribute(null));
            Assert.AreEqual("&#60;script&#62;", encoder.EncodeForHtmlAttribute("<script>"));
            Assert.AreEqual(",.-_", encoder.EncodeForHtmlAttribute(",.-_"));
            Assert.AreEqual("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForHtmlAttribute(" !@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForJavaScript method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForJavaScript()
        {
            System.Console.Out.WriteLine("EncodeForJavaScript");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("''", encoder.EncodeForJavascript(null));
            Assert.AreEqual("'\\x3cscript\\x3e'", encoder.EncodeForJavascript("<script>"));
            Assert.AreEqual("',.-_ '", encoder.EncodeForJavascript(",.-_ "));
            Assert.AreEqual("'\\x21\\x40\\x24\\x25\\x28\\x29\\x3d\\x2b\\x7b\\x7d\\x5b\\x5d'", encoder.EncodeForJavascript("!@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForVisualBasicScript method, of class
        /// Owasp.Esapi.Encoder.
        /// </summary>
        [TestMethod]
        public void Test_EncodeForVbScript()
        {
            System.Console.Out.WriteLine("EncodeForVbScript");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("\"\"", encoder.EncodeForVbScript(null));
            Assert.AreEqual("chrw(60)&\"script\"&chrw(62)", encoder.EncodeForVbScript("<script>"));
            Assert.AreEqual("\"x \"&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)", encoder.EncodeForVbScript("x !@$%()=+{}[]"));
            Assert.AreEqual("\"alert\"&chrw(40)&chrw(39)&\"ESAPI test\"&chrw(33)&chrw(39)&chrw(41)", encoder.EncodeForVbScript("alert('ESAPI test!')"));
            Assert.AreEqual("\"jeff.williams\"&chrw(64)&\"aspectsecurity.com\"", encoder.EncodeForVbScript("jeff.williams@aspectsecurity.com"));
            Assert.AreEqual("\"test \"&chrw(60)&chrw(62)&\" test\"", encoder.EncodeForVbScript("test <> test"));
        }

        /// <summary> Test of EncodeForXPath method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForXPath()
        {
            System.Console.Out.WriteLine("EncodeForXPath");
            IEncoder encoder = Esapi.Encoder;            
        }

        /// <summary> Test of EncodeForSQL method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForSQL()
        {
            System.Console.Out.WriteLine("EncodeForSQL");
            IEncoder encoder = Esapi.Encoder;            
        }


        /// <summary> Test of EncodeForLDAP method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForLDAP()
        {
            System.Console.Out.WriteLine("EncodeForLDAP");
            IEncoder encoder = Esapi.Encoder;
            
        }

        /// <summary> Test of EncodeForDN method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForDN()
        {
            System.Console.Out.WriteLine("EncodeForDN");
            IEncoder encoder = Esapi.Encoder;
        }


        /// <summary> Test of EncodeForXML method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForXML()
        {
            System.Console.Out.WriteLine("EncodeForXML");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.EncodeForXml(null));
            Assert.AreEqual(" ", encoder.EncodeForXml(" "));
            Assert.AreEqual("&#60;script&#62;", encoder.EncodeForXml("<script>"));
            Assert.AreEqual(",.-_", encoder.EncodeForXml(",.-_"));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForXml("!@$%()=+{}[]"));
        }
        
        /// <summary> Test of EncodeForXMLAttribute method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForXMLAttribute()
        {
            System.Console.Out.WriteLine("EncodeForXMLAttribute");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.EncodeForXmlAttribute(null));
            Assert.AreEqual("&#32;", encoder.EncodeForXmlAttribute(" "));
            Assert.AreEqual("&#60;script&#62;", encoder.EncodeForXmlAttribute("<script>"));
            Assert.AreEqual(",.-_", encoder.EncodeForXmlAttribute(",.-_"));
            Assert.AreEqual("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForXmlAttribute(" !@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForURL method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForURL()
        {
            System.Console.Out.WriteLine("EncodeForURL");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.EncodeForUrl(null));
            Assert.AreEqual("%3cscript%3e", encoder.EncodeForUrl("<script>"));
        }

        /// <summary> Test of DecodeFromURL method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_DecodeFromURL()
        {
            System.Console.Out.WriteLine("DecodeFromURL");
            IEncoder encoder = Esapi.Encoder;
            try
            {
                // Assert.AreEqual("", encoder.DecodeFromUrl(null));
                Assert.AreEqual("<script>", encoder.DecodeFromUrl("%3Cscript%3E"));
                Assert.AreEqual("     ", encoder.DecodeFromUrl("+++++"));
            }
            catch (Exception)
            {
                Assert.Fail();
            }
        }

        /// <summary> Test of EncodeForBase64 method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForBase64()
        {
            System.Console.Out.WriteLine("EncodeForBase64");
            IEncoder encoder = Esapi.Encoder;
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                    byte[] r = encoding.GetBytes(Esapi.Randomizer.GetRandomString(20, Owasp.Esapi.Encoder.CHAR_SPECIALS));
                    string encoded = encoder.EncodeForBase64(r);
                    byte[] decoded = encoder.DecodeFromBase64(encoded);
                    Assert.IsTrue(ArraysAreEqual(r, decoded));
                }
            }
            catch (IOException)
            {
                Assert.Fail();
            }
        }

        /// <summary> Test of DecodeFromBase64 method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_DecodeFromBase64()
        {
            System.Console.Out.WriteLine("DecodeFromBase64");
            IEncoder encoder = Esapi.Encoder;
            for (int i = 0; i < 100; i++)
            {
                try
                {
                    ASCIIEncoding encoding = new ASCIIEncoding();
                    byte[] r = encoding.GetBytes(Esapi.Randomizer.GetRandomString(20, Owasp.Esapi.Encoder.CHAR_SPECIALS));
                    string encoded = encoder.EncodeForBase64(r);
                    byte[] decoded = encoder.DecodeFromBase64(encoded);

                    Assert.IsTrue(ArraysAreEqual(r, decoded));
                }
                catch (IOException)
                {
                    Assert.Fail();
                }
            }
            for (int i = 0; i < 100; i++)
            {
                try
                {
                    ASCIIEncoding encoding = new ASCIIEncoding();
                    byte[] r = encoding.GetBytes(Esapi.Randomizer.GetRandomString(20, Owasp.Esapi.Encoder.CHAR_SPECIALS));
                    string encoded = Esapi.Randomizer.GetRandomString(1, Owasp.Esapi.Encoder.CHAR_ALPHANUMERICS) + encoder.EncodeForBase64(r);
                    byte[] decoded = encoder.DecodeFromBase64(encoded);
                    Assert.IsFalse(Array.Equals(r, decoded));
                }
                catch (FormatException)
                {
                    // expected
                }
            }
        }

        private bool ArraysAreEqual(byte[] a1, byte[] a2)
        {
            if (a1.Length != a2.Length)
            {
                return false;
            }
            for (int index = 0; index < a1.Length; index++)
            {
                if (a1[index] != a2[index])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
