/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI) 
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/.NET_ESAPI.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using NUnit.Framework;
using Owasp.Esapi.Errors;
using System.IO;
using Owasp.Esapi.Interfaces;
using System.Text;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class EncoderTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class EncoderTest
    {

        /// <summary> Instantiates a new encoder test.
        /// 
        /// </summary>        
        public EncoderTest():this(null)
        {
        }


        /// <summary> Instantiates a new encoder test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public EncoderTest(string testName)            
        {
        }

        /// <summary> Test of Canonicalize method, of class Owasp.Esapi.Validator.
        /// 
        /// </summary>
        /// <throws>  ValidationException </throws>
        [Test]
        public void Test_Canonicalize()
        {
            System.Console.Out.WriteLine("Canonicalize");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("<script>alert(\"hello\");</script>", encoder.Canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E"));
            try
            {
                Assert.AreEqual("<script", encoder.Canonicalize("%253Cscript"));
            }
            catch (IntrusionException e)
            {
                // expected
            }
            try
            {
                Assert.AreEqual("<script", encoder.Canonicalize("&#37;3Cscript"));
            }
            catch (IntrusionException e)
            {
                // expected
            }
        }

        /// <summary> Test of Normalize method, of class Owasp.Esapi.Validator.
        /// 
        /// </summary>
        /// <throws>  ValidationException </throws>
        /// <summary>             the validation exception
        /// </summary>
        [Test]
        public void Test_Normalize()
        {
            System.Console.Out.WriteLine("Normalize");
            Assert.AreEqual(Esapi.Encoder().Normalize("é à î _ @ \" < > \u20A0"), "e a i _ @ \" < > ");
        }

        [Test]
        public void Test_EntityEncode()
        {
            System.Console.Out.WriteLine("EntityEncode");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("&lt;script&gt;", encoder.EncodeForHtml("&lt;script&gt;"));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForHtml("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;"));
        }

        /// <summary> Test of EncodeForHTML method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForHTML()
        {
            System.Console.Out.WriteLine("EncodeForHTML");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("", encoder.EncodeForHtml(null));
            Assert.AreEqual("&lt;script&gt;", encoder.EncodeForHtml("<script>"));
            Assert.AreEqual(",.-_ ", encoder.EncodeForHtml(",.-_ "));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForHtml("!@$%()=+{}[]"));
            Assert.AreEqual("dir&amp;", encoder.EncodeForHtml("dir&"));
            Assert.AreEqual("one&amp;two", encoder.EncodeForHtml("one&two"));
        }

        /// <summary> Test of EncodeForHTMLAttribute method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForHTMLAttribute()
        {
            System.Console.Out.WriteLine("EncodeForHTMLAttribute");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("&lt;script&gt;", encoder.EncodeForHtmlAttribute("<script>"));
            Assert.AreEqual(",.-_", encoder.EncodeForHtmlAttribute(",.-_"));
            Assert.AreEqual("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForHtmlAttribute(" !@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForJavaScript method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForJavascript()
        {
            System.Console.Out.WriteLine("EncodeForJavascript");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("&lt;script&gt;", encoder.EncodeForJavascript("<script>"));
            Assert.AreEqual(",.-_ ", encoder.EncodeForJavascript(",.-_ "));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForJavascript("!@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForVisualBasicScript method, of class
        /// Owasp.Esapi.Encoder.
        /// </summary>
        [Test]
        public void Test_EncodeForVBScript()
        {
            System.Console.Out.WriteLine("EncodeForVBScript");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("&lt;script&gt;", encoder.EncodeForVbScript("<script>"));
            Assert.AreEqual(",.-_ ", encoder.EncodeForVbScript(",.-_ "));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForVbScript("!@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForXPath method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForXPath()
        {
            System.Console.Out.WriteLine("EncodeForXPath");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("&#39;or 1&#61;1", encoder.EncodeForXPath("'or 1=1"));
        }

        /// <summary> Test of EncodeForSQL method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForSQL()
        {
            System.Console.Out.WriteLine("EncodeForSQL");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("Jeff'' or ''1''=''1", encoder.EncodeForSql("Jeff' or '1'='1"), "Single quote");
        }


        /// <summary> Test of EncodeForLDAP method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForLDAP()
        {
            System.Console.Out.WriteLine("EncodeForLDAP");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("Hi This is a test #çà", encoder.EncodeForLdap("Hi This is a test #çà"), "No special characters to escape");
            Assert.AreEqual("Hi \\00", encoder.EncodeForLdap("Hi \u0000"), "Zeros");
            Assert.AreEqual("Hi \\28This\\29 = is \\2a a \\5c test # ç à ô", encoder.EncodeForLdap("Hi (This) = is * a \\ test # ç à ô"), "LDAP Christams Tree");
        }

        /// <summary> Test of EncodeForDN method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForDN()
        {
            System.Console.Out.WriteLine("EncodeForDN");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("Helloé", encoder.EncodeForDn("Helloé"), "No special characters to escape");
            Assert.AreEqual("\\# Helloé", encoder.EncodeForDn("# Helloé"), "leading #");
            Assert.AreEqual("\\ Helloé", encoder.EncodeForDn(" Helloé"), "leading space");
            Assert.AreEqual("Helloé\\ ", encoder.EncodeForDn("Helloé "), "trailing space");
            Assert.AreEqual("Hello\\<\\>", encoder.EncodeForDn("Hello<>"), "less than greater than");
            Assert.AreEqual("\\  \\ ", encoder.EncodeForDn("   "), "only 3 spaces");
            Assert.AreEqual("\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", encoder.EncodeForDn(" Hello\\ + , \"World\" ; "), "Christmas Tree DN");
        }


        /// <summary> Test of EncodeForXML method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForXML()
        {
            System.Console.Out.WriteLine("EncodeForXML");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual(" ", encoder.EncodeForXml(" "));
            Assert.AreEqual("&lt;script&gt;", encoder.EncodeForXml("<script>"));
            Assert.AreEqual(",.-_", encoder.EncodeForXml(",.-_"));
            Assert.AreEqual("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForXml("!@$%()=+{}[]"));
        }



        /// <summary> Test of EncodeForXMLAttribute method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForXMLAttribute()
        {
            System.Console.Out.WriteLine("EncodeForXMLAttribute");
            IEncoder encoder = Esapi.Encoder();
            Assert.AreEqual("&#32;", encoder.EncodeForXmlAttribute(" "));
            Assert.AreEqual("&lt;script&gt;", encoder.EncodeForXmlAttribute("<script>"));
            Assert.AreEqual(",.-_", encoder.EncodeForXmlAttribute(",.-_"));
            Assert.AreEqual("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", encoder.EncodeForXmlAttribute(" !@$%()=+{}[]"));
        }

        /// <summary> Test of EncodeForURL method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForURL()
        {
            System.Console.Out.WriteLine("EncodeForURL");
            IEncoder encoder = Esapi.Encoder();
            // Note, because we are using the URL encoding built into ASP.NET System.Web.HttpUtility,
            // the entity characters are lower case (in Java test value is %3Cscript%3E
            Assert.AreEqual("%3cscript%3e", encoder.EncodeForUrl("<script>"));
        }

        /// <summary> Test of DecodeFromURL method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_DecodeFromURL()
        {
            System.Console.Out.WriteLine("DecodeFromURL");
            IEncoder encoder = Esapi.Encoder();
            try
            {
                Assert.AreEqual("<script>", encoder.DecodeFromUrl("%3Cscript%3E"));
                for (int i = 0; i < 100; i++)
                {
                    string r = Esapi.Randomizer().GetRandomString(20, Encoder.CHAR_PASSWORD);
                    string encoded = encoder.EncodeForUrl(r);
                    string decoded = encoder.DecodeFromUrl(encoded);
                    Assert.AreEqual(r, decoded);
                }
            }
            catch (System.Exception e)
            {
                Assert.Fail();
            }
        }

        /// <summary> Test of EncodeForBase64 method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_EncodeForBase64()
        {
            System.Console.Out.WriteLine("EncodeForBase64");
            IEncoder encoder = Esapi.Encoder();
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    System.Text.ASCIIEncoding  encoding=new System.Text.ASCIIEncoding();                       
                    byte[] r = encoding.GetBytes(Esapi.Randomizer().GetRandomString(20, Encoder.CHAR_SPECIALS));
                    string encoded = encoder.EncodeForBase64(r, Esapi.Randomizer().RandomBoolean);
                    byte[] decoded = encoder.DecodeFromBase64(encoded);
                    
                    Assert.IsTrue(ArraysAreEqual(r, decoded));
                }
            }
            catch (IOException e)
            {
                Assert.Fail();
            }
        }

        /// <summary> Test of DecodeFromBase64 method, of class Owasp.Esapi.Encoder.</summary>
        [Test]
        public void Test_DecodeFromBase64()
        {
            System.Console.Out.WriteLine("DecodeFromBase64");
            IEncoder encoder = Esapi.Encoder();
            for (int i = 0; i < 100; i++)
            {
                try
                {
                    System.Text.ASCIIEncoding  encoding = new System.Text.ASCIIEncoding();
                    byte[] r = encoding.GetBytes(Esapi.Randomizer().GetRandomString(20, Encoder.CHAR_SPECIALS));

                    string encoded = encoder.EncodeForBase64(r, Esapi.Randomizer().RandomBoolean);
                    byte[] decoded = encoder.DecodeFromBase64(encoded);
                    
                    Assert.IsTrue(ArraysAreEqual(r, decoded));
                }
                catch (IOException e)
                {
                    Assert.Fail();
                }
            }
            for (int i = 0; i < 100; i++)
            {
                try
                {
                    System.Text.ASCIIEncoding  encoding = new System.Text.ASCIIEncoding();
                    byte[] r = encoding.GetBytes(Esapi.Randomizer().GetRandomString(20, Encoder.CHAR_SPECIALS));
                    string encoded = Esapi.Randomizer().GetRandomString(1, Encoder.CHAR_ALPHANUMERICS) + encoder.EncodeForBase64(r, Esapi.Randomizer().RandomBoolean);
                    byte[] decoded = encoder.DecodeFromBase64(encoded);
                    Assert.IsFalse(Array.Equals(r, decoded));
                }
                catch (FormatException e)
                {
                    // expected
                }
            }
        }
        
        public bool ArraysAreEqual(byte[] a1, byte[] a2)
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
