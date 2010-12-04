using System;
using System.Collections.Generic;
using System.IO;
using EsapiTest.Surrogates;
using NUnit.Framework;
using Owasp.Esapi;
using Owasp.Esapi.Codecs;
using Owasp.Esapi.Configuration;
using Rhino.Mocks;
using RMC = Rhino.Mocks.Constraints;

namespace EsapiTest.Codecs
{
    /// <summary>
    /// Summary description for codec test
    /// </summary>
    [TestFixture]
    class CodecTest
    {
        private HtmlCodec HTMLCodec;
        private UrlCodec URLCodec;



        [SetUp]
        public void InitializeTest()
        {
            HTMLCodec = new HtmlCodec();
            URLCodec = new UrlCodec();
        }



        #region HTML Codec Test
        /*
        [Test]
        public void testHtmlEncode()
        {
            Assert.AreEqual("test", HTMLCodec.Encode("test"));
        }

        [Test]
        public void testHtmlEncodeChar()
        {
            Assert.AreEqual("&lt;", HTMLCodec.Encode("<"));
        }

        [Test]
        public void testHtmlEncodeChar0x100()
	    {
		    char input = '\x100';
		    String inStr = Convert.ToString(input);
            input = Convert.ToChar(inStr);
		    String expected = "&#x100;";
		    String result;

            result = HTMLCodec.Encode(inStr);
		    // this should be escaped
        	Assert.False(inStr.Equals(result));
		    // UTF-8 encoded and then percent escaped
        	Assert.AreEqual(expected, result);
	    }

        [Test]
        public void testHtmlEncodeStr0x100()
	    {
		    char input = '\x100';
            String inStr = Convert.ToString(input);
		    String expected = "&#x100;";
		    String result;

            result = HTMLCodec.Encode(inStr);
		    // this should be escaped
            Assert.False(inStr.Equals(result));
		    // UTF-8 encoded and then percent escaped
        	Assert.AreEqual(expected, result);
	    }*/

        [Test]
        public void Test_HtmlDecodeDecimalEntities()
        {
            Assert.AreEqual("test!", HTMLCodec.Decode("&#116;&#101;&#115;&#116;!"));            
        }

        [Test]
        public void Test_HtmlDecodeHexEntitites()
        {
            Assert.AreEqual("test!", HTMLCodec.Decode("&#x74;&#x65;&#x73;&#x74;!"));
        }

        [Test]
        public void Test_HtmlDecodeInvalidAttribute()
        {
            Assert.AreEqual("&mike;", HTMLCodec.Decode("&mike;"));
        }

        [Test]
        public void Test_HtmlDecodeAmp()
        {
            Assert.AreEqual("&", HTMLCodec.Decode("&amp;"));
            Assert.AreEqual("&X", HTMLCodec.Decode("&amp;X"));
            Assert.AreEqual("&", HTMLCodec.Decode("&amp"));
            Assert.AreEqual("&X",HTMLCodec.Decode("&ampX"));           

        }

        [Test]
        public void Test_HtmlDecodeLt()
        {

            Assert.AreEqual("<", HTMLCodec.Decode("&lt;"));
            Assert.AreEqual("<X", HTMLCodec.Decode("&lt;X"));
            Assert.AreEqual("<", HTMLCodec.Decode("&lt"));
            Assert.AreEqual("<X", HTMLCodec.Decode("&ltX"));

        }

        [Test]
        public void Test_HtmlDecodeSup1()
        {
            Assert.AreEqual("\u00B9", HTMLCodec.Decode("&sup1;"));
            Assert.AreEqual("\u00B9X", HTMLCodec.Decode("&sup1;X"));
            Assert.AreEqual("\u00B9", HTMLCodec.Decode("&sup1"));
            Assert.AreEqual("\u00B9X", HTMLCodec.Decode("&sup1X"));

        }

        [Test]
        public void Test_HtmlDecodeSup2()
        {
            Assert.AreEqual("\u00B9", HTMLCodec.Decode("&sup2;"));
            Assert.AreEqual("\u00B9X", HTMLCodec.Decode("&sup2;X"));
            Assert.AreEqual("\u00B9", HTMLCodec.Decode("&sup2"));
            Assert.AreEqual("\u00B9X", HTMLCodec.Decode("&sup2X"));

        }

        [Test]
        public void Test_HtmlDecodeSup3()
        {
            Assert.AreEqual("\u00B3", HTMLCodec.Decode("&sup3;"));
            Assert.AreEqual("\u00B3X", HTMLCodec.Decode("&sup3;X"));
            Assert.AreEqual("\u00B3", HTMLCodec.Decode("&sup3"));
            Assert.AreEqual("\u00B3X", HTMLCodec.Decode("&sup3X"));

        }

        [Test]
        public void Test_HtmlDecodeSup()
        {
            Assert.AreEqual("\u2283", HTMLCodec.Decode("&sup;"));
            Assert.AreEqual("\u2283X", HTMLCodec.Decode("&sup;X"));
            Assert.AreEqual("\u2283", HTMLCodec.Decode("&sup"));
            Assert.AreEqual("\u2283X", HTMLCodec.Decode("&supX"));
        }

        [Test]
        public void Test_HtmlDecodeSupe()
        {
            Assert.AreEqual("\u2287", HTMLCodec.Decode("&supe;"));
            Assert.AreEqual("\u2287X", HTMLCodec.Decode("&supe;X"));
            Assert.AreEqual("\u2287", HTMLCodec.Decode("&supe"));
            Assert.AreEqual("\u2287X", HTMLCodec.Decode("&supeX"));
        }

        [Test]
        public void Test_HtmlDecodePi()
        {
            Assert.AreEqual("\u03C0", HTMLCodec.Decode("&pi;"));
            Assert.AreEqual("\u03C0X", HTMLCodec.Decode("&pi;X"));
            Assert.AreEqual("\u03C0", HTMLCodec.Decode("&pi"));
            Assert.AreEqual("\u03C0X", HTMLCodec.Decode("&piX"));
        }

        [Test]
        public void Test_HtmlDecodePiv()
        {
            Assert.AreEqual("\u03D6", HTMLCodec.Decode("&piv;"));
            Assert.AreEqual("\u03D6X", HTMLCodec.Decode("&piv;X"));
            Assert.AreEqual("\u03D6", HTMLCodec.Decode("&piv"));
            Assert.AreEqual("\u03D6X", HTMLCodec.Decode("&pivX"));
        }

        [Test]
        public void Test_HtmlDecodeTheta()
        {
            Assert.AreEqual("\u03B8", HTMLCodec.Decode("&theta;"));
            Assert.AreEqual("\u03B8X", HTMLCodec.Decode("&theta;X"));
            Assert.AreEqual("\u03B8", HTMLCodec.Decode("&theta"));
            Assert.AreEqual("\u03B8X", HTMLCodec.Decode("&thetaX"));
        }

        [Test]
        public void Test_HtmlDecodeThetasym()
        {
            Assert.AreEqual("\u03D1", HTMLCodec.Decode("&thetasym;"));
            Assert.AreEqual("\u03D1X", HTMLCodec.Decode("&thetasym;X"));
            Assert.AreEqual("\u03D1", HTMLCodec.Decode("&thetasym"));
            Assert.AreEqual("\u03D1X", HTMLCodec.Decode("&thetasymX"));
        }
        #endregion


        #region URL Codec Test

        [Test]
        public void URL_EcodeTest()
        {
            Assert.AreEqual("%3c", URLCodec.Encode("<"));
            Assert.AreEqual("%3cX", URLCodec.Encode("<X"));
        }

        [Test]
        public void URL_DecodeTest()
        {
            Assert.AreEqual("<", URLCodec.Decode("%3c"));
            Assert.AreEqual("<", URLCodec.Decode("%3C"));
            Assert.AreEqual("<X", URLCodec.Decode("%3CX"));
        }

      


        #endregion
    }
}
