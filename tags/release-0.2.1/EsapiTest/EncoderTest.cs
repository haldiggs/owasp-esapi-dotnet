using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Codecs;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Interfaces;
using Rhino.Mocks;
using Rhino.Mocks.Constraints;
using EsapiTest.Surrogates;

namespace EsapiTest
{
    /// <summary>
    /// Summary description for EncoderTest
    /// </summary>
    [TestClass]
    public class EncoderTest
    {        
        [TestInitialize]
        public void InitializeTest()
        {
            Esapi.Reset();
            EsapiConfig.Reset();

            SurrogateEncoder.DefaultEncoder = null;
        }

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
            Assert.AreEqual("", encoder.Encode(BuiltinCodecs.Html, null));
            // test invalid characters are replaced with spaces
            Assert.AreEqual("a&#0;b&#4;c&#128;d&#150;e&#159;f&#9;g", encoder.Encode(BuiltinCodecs.Html, "a" + (char)0 + "b" + (char)4 + "c" + (char)128 + "d" + (char)150 + "e" + (char)159 + "f" + (char)9 + "g"));        
            Assert.AreEqual("&#60;script&#62;", encoder.Encode(BuiltinCodecs.Html, "<script>"));
            Assert.AreEqual("&#38;lt&#59;script&#38;gt&#59;", encoder.Encode(BuiltinCodecs.Html, "&lt;script&gt;"));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.Encode(BuiltinCodecs.Html, "!@$%()=+{}[]"));
            // Assert.AreEqual("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", encoder.Encode(BuiltinCodec.Html, encoder.Canonicalize("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;") ) );
            Assert.AreEqual(",.-_ ", encoder.Encode(BuiltinCodecs.Html, ",.-_ "));
            Assert.AreEqual("dir&#38;", encoder.Encode(BuiltinCodecs.Html, "dir&"));
            Assert.AreEqual("one&#38;two", encoder.Encode(BuiltinCodecs.Html, "one&two"));
            Assert.AreEqual("" + (char)12345 + (char)65533 + (char)1244, "" + (char)12345 + (char)65533 + (char)1244 );
        }

        /// <summary> Test of EncodeForHtmlAttribute method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForHtmlAttribute()
        {
            System.Console.Out.WriteLine("EncodeForHtmlAttribute");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.Encode(BuiltinCodecs.HtmlAttribute, null));
            Assert.AreEqual("&#60;script&#62;", encoder.Encode(BuiltinCodecs.HtmlAttribute, "<script>"));
            Assert.AreEqual(",.-_", encoder.Encode(BuiltinCodecs.HtmlAttribute, ",.-_"));
            Assert.AreEqual("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.Encode(BuiltinCodecs.HtmlAttribute, " !@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForJavaScript method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForJavaScript()
        {
            System.Console.Out.WriteLine("EncodeForJavaScript");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("''", encoder.Encode(BuiltinCodecs.JavaScript, null));
            Assert.AreEqual("'\\x3cscript\\x3e'", encoder.Encode(BuiltinCodecs.JavaScript, "<script>"));
            Assert.AreEqual("',.-_ '", encoder.Encode(BuiltinCodecs.JavaScript, ",.-_ "));
            Assert.AreEqual("'\\x21\\x40\\x24\\x25\\x28\\x29\\x3d\\x2b\\x7b\\x7d\\x5b\\x5d'", encoder.Encode(BuiltinCodecs.JavaScript, "!@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForVisualBasicScript method, of class
        /// Owasp.Esapi.Encoder.
        /// </summary>
        [TestMethod]
        public void Test_EncodeForVbScript()
        {
            System.Console.Out.WriteLine("EncodeForVbScript");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("\"\"", encoder.Encode(BuiltinCodecs.VbScript, null));
            Assert.AreEqual("chrw(60)&\"script\"&chrw(62)", encoder.Encode(BuiltinCodecs.VbScript, "<script>"));
            Assert.AreEqual("\"x \"&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)", encoder.Encode(BuiltinCodecs.VbScript, "x !@$%()=+{}[]"));
            Assert.AreEqual("\"alert\"&chrw(40)&chrw(39)&\"ESAPI test\"&chrw(33)&chrw(39)&chrw(41)", encoder.Encode(BuiltinCodecs.VbScript, "alert('ESAPI test!')"));
            Assert.AreEqual("\"jeff.williams\"&chrw(64)&\"aspectsecurity.com\"", encoder.Encode(BuiltinCodecs.VbScript, "jeff.williams@aspectsecurity.com"));
            Assert.AreEqual("\"test \"&chrw(60)&chrw(62)&\" test\"", encoder.Encode(BuiltinCodecs.VbScript, "test <> test"));
        }


        /// <summary> Test of EncodeForXML method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForXML()
        {
            System.Console.Out.WriteLine("EncodeForXML");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.Encode(BuiltinCodecs.Xml, null));
            Assert.AreEqual(" ", encoder.Encode(BuiltinCodecs.Xml, " "));
            Assert.AreEqual("&#60;script&#62;", encoder.Encode(BuiltinCodecs.Xml, "<script>"));
            Assert.AreEqual(",.-_", encoder.Encode(BuiltinCodecs.Xml, ",.-_"));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.Encode(BuiltinCodecs.Xml, "!@$%()=+{}[]"));
        }
        
        /// <summary> Test of EncodeForXMLAttribute method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForXMLAttribute()
        {
            System.Console.Out.WriteLine("EncodeForXMLAttribute");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.Encode(BuiltinCodecs.XmlAttribute, null));
            Assert.AreEqual("&#32;", encoder.Encode(BuiltinCodecs.XmlAttribute, " "));
            Assert.AreEqual("&#60;script&#62;", encoder.Encode(BuiltinCodecs.XmlAttribute, "<script>"));
            Assert.AreEqual(",.-_", encoder.Encode(BuiltinCodecs.XmlAttribute, ",.-_"));
            Assert.AreEqual("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.Encode(BuiltinCodecs.XmlAttribute, " !@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForURL method, of class Owasp.Esapi.Encoder.</summary>
        [TestMethod]
        public void Test_EncodeForURL()
        {
            System.Console.Out.WriteLine("EncodeForURL");
            IEncoder encoder = Esapi.Encoder;
            Assert.AreEqual("", encoder.Encode(BuiltinCodecs.Url, null));
            Assert.AreEqual("%3cscript%3e", encoder.Encode(BuiltinCodecs.Url, "<script>"));
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
                Assert.AreEqual("<script>", encoder.Decode(BuiltinCodecs.Url, "%3Cscript%3E"));
                Assert.AreEqual("     ", encoder.Decode(BuiltinCodecs.Url, "+++++"));
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
                    string random = Esapi.Randomizer.GetRandomString(20, Owasp.Esapi.CharSetValues.Specials);
                    string encoded = encoder.Encode(BuiltinCodecs.Base64, random);
                    string decoded = encoder.Decode(BuiltinCodecs.Base64, encoded);
                    Assert.AreEqual(random, decoded);
                }
            }
            catch (IOException)
            {
                Assert.Fail();
            }
        }

        [TestMethod]
        public void Test_AddCodec()
        {
            MockRepository mocks = new MockRepository();

            string codecName = Guid.NewGuid().ToString();
            ICodec codec = mocks.StrictMock<ICodec>();

            Esapi.Encoder.AddCodec(codecName, codec);
            Assert.ReferenceEquals(Esapi.Encoder.GetCodec(codecName), codec);        
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_AddWrongCodecName()
        {
            MockRepository mocks = new MockRepository();

            Esapi.Encoder.AddCodec(null, mocks.StrictMock<ICodec>());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_AddDuplicateCodec()
        {
            MockRepository mocks = new MockRepository();

            string codecName  = Guid.NewGuid().ToString();
            
            Esapi.Encoder.AddCodec(codecName, mocks.StrictMock<ICodec>());
            Esapi.Encoder.AddCodec(codecName, mocks.StrictMock<ICodec>());
        }

        [TestMethod]
        public void Test_RemoveCodec()
        {
            MockRepository mocks = new MockRepository();

            string codecName = Guid.NewGuid().ToString();
            ICodec codec = mocks.StrictMock<ICodec>();

            Esapi.Encoder.AddCodec(codecName, codec);
            Assert.ReferenceEquals(Esapi.Encoder.GetCodec(codecName), codec);      

            Esapi.Encoder.RemoveCodec(codecName);
            Assert.IsNull(Esapi.Encoder.GetCodec(codecName));
        }

        [TestMethod]
        public void Test_Encode()
        {
            MockRepository mocks = new MockRepository();

            string testString = Guid.NewGuid().ToString();
            string codecName = Guid.NewGuid().ToString();

            ICodec codec = mocks.StrictMock<ICodec>();
            Expect.Call(codec.Encode(testString)).Return(testString);
            mocks.ReplayAll();

            Esapi.Encoder.AddCodec(codecName, codec);
            Assert.ReferenceEquals(Esapi.Encoder.GetCodec(codecName), codec);        

            Assert.AreEqual(testString, Esapi.Encoder.Encode(codecName, testString));
            mocks.VerifyAll();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void Test_EncodeWrongCodecName()
        {
            string codecName = Guid.NewGuid().ToString();

            Esapi.Encoder.Encode(codecName, "test");
        }

        [TestMethod]
        public void Test_Decode()
        {
            MockRepository mocks = new MockRepository();

            string testString = Guid.NewGuid().ToString();
            string codecName = Guid.NewGuid().ToString();

            ICodec codec = mocks.StrictMock<ICodec>();
            Expect.Call(codec.Decode(testString)).Return(testString);
            mocks.ReplayAll();

            Esapi.Encoder.AddCodec(codecName, codec);
            Assert.ReferenceEquals(Esapi.Encoder.GetCodec(codecName), codec);        

            Assert.AreEqual(testString, Esapi.Encoder.Decode(codecName, testString));
            mocks.VerifyAll();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void Test_DecodeWrongCodecName()
        {
            string codecName = Guid.NewGuid().ToString();

            Esapi.Encoder.Decode(codecName, "test");
        }

        [TestMethod]
        public void Test_CanonicalizeNullCodec()
        {
            List<string>  codecs = new List<string>();
            codecs.Add(null);

            Esapi.Encoder.Canonicalize(codecs, "\0", false);
        }

        /// <summary>
        /// Tests loading of configuration defined encoder
        /// </summary>
        [TestMethod]
        public void Test_LoadCustom()
        {
            // Set new
            EsapiConfig.Instance.Encoder.Type = typeof(SurrogateEncoder).AssemblyQualifiedName;

            IEncoder encoder = Esapi.Encoder;
            Assert.IsTrue(encoder.GetType().Equals(typeof(SurrogateEncoder)));
        }

        /// <summary>
        /// Tests loading of assembly defined codecs in a configuration defined
        /// encoder
        /// </summary>
        [TestMethod]        
        public void Test_LoadCustomAddinAssembly()
        {
            MockRepository mocks = new MockRepository();

            // Set new
            EsapiConfig.Instance.Encoder.Type = typeof(SurrogateEncoder).AssemblyQualifiedName;

            // Set assemblies to load
            AddinAssemblyElement addinAssembly = new AddinAssemblyElement();
            addinAssembly.Name =  typeof(Esapi).Assembly.FullName;
            EsapiConfig.Instance.Encoder.Codecs.Assemblies.Add(addinAssembly);
            
            // Set mock expectations
            IEncoder mockEncoder = mocks.StrictMock<IEncoder>();
            
            // Load default
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.Base64, null); }).Constraints(Is.Equal(BuiltinCodecs.Base64), Is.Anything());
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.Html, null); }).Constraints(Is.Equal(BuiltinCodecs.Html), Is.Anything());
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.HtmlAttribute, null); }).Constraints(Is.Equal(BuiltinCodecs.HtmlAttribute), Is.Anything());
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.JavaScript, null); }).Constraints(Is.Equal(BuiltinCodecs.JavaScript), Is.Anything());
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.Url, null); }).Constraints(Is.Equal(BuiltinCodecs.Url), Is.Anything());
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.VbScript, null); }).Constraints(Is.Equal(BuiltinCodecs.VbScript), Is.Anything());
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.Xml, null); }).Constraints(Is.Equal(BuiltinCodecs.Xml), Is.Anything());
            Expect.Call(delegate { mockEncoder.AddCodec(BuiltinCodecs.XmlAttribute, null); }).Constraints(Is.Equal(BuiltinCodecs.XmlAttribute), Is.Anything());
            mocks.ReplayAll();

            // Create and test
            SurrogateEncoder.DefaultEncoder = mockEncoder;
            IEncoder encoder = Esapi.Encoder;

            Assert.IsTrue(encoder.GetType().Equals(typeof(SurrogateEncoder)));
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
            EsapiConfig.Instance.Encoder.Type = typeof(SurrogateEncoder).AssemblyQualifiedName;
            
            // Set codecs to load
            string[] codecNames = new [] { Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), Guid.NewGuid().ToString() };
            foreach (string codecName in codecNames) {
                CodecElement codecElement = new CodecElement();
                codecElement.Name = codecName;
                codecElement.Type = typeof(SurrogateCodec).AssemblyQualifiedName;

                EsapiConfig.Instance.Encoder.Codecs.Add(codecElement);
            }
            
            // Set mock expectations
            IEncoder mockEncoder = mocks.StrictMock<IEncoder>();

            // Custom codecs are loaded and are of proper type
            foreach (string codecName in codecNames) {
                Expect.Call(delegate { mockEncoder.AddCodec(codecName, null); }).Constraints(Is.Equal(codecName), Is.TypeOf<SurrogateCodec>());
            }
            mocks.ReplayAll();

            // Create and test
            SurrogateEncoder.DefaultEncoder = mockEncoder;
            IEncoder encoder = Esapi.Encoder;

            Assert.IsTrue(encoder.GetType().Equals(typeof(SurrogateEncoder)));
            mocks.VerifyAll();
        }
    }
}
