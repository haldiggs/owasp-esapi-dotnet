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
        private HtmlCodec HTMLCodec = new HtmlCodec();

        [SetUp]
        public void InitializeTest()
        {
            //None
        }

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
            //Assert.AreEqual("&", HTMLCodec.Decode(char(c)));
            Assert.AreEqual("&X", HTMLCodec.Decode("&amp;X"));
            Assert.AreEqual("&", HTMLCodec.Decode("&amp"));
            Assert.AreEqual("&X",HTMLCodec.Decode("&ampX"));

        }

    }
}
