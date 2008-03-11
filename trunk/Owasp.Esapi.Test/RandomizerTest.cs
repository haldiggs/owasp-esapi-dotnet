/// <summary> OWASP Enterprise Security API .NET (ESAPI.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using NUnit.Framework;
using System.Collections;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class RandomizerTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
   
    [TestFixture]
    public class RandomizerTest
    {
        /// <summary> Instantiates a new randomizer test.
        /// 
        /// </summary>
        public RandomizerTest():this(null)
        {
        }
        
        /// <summary> Instantiates a new randomizer test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public RandomizerTest(string testName)
        {
        }

        /// <summary> Test of GetRandomString method, of class Owasp.Esapi.Randomizer.</summary>
        [Test]
        public void Test_GetRandomString()
        {
            System.Console.Out.WriteLine("GetRandomString");
            int length = 20;
            IRandomizer randomizer = Esapi.Randomizer();
            for (int i = 0; i < 100; i++)
            {
                string result = randomizer.GetRandomString(length, Encoder.CHAR_ALPHANUMERICS);
                Assert.AreEqual(length, result.Length);
            }
        }

        /// <summary> Test of GetRandomInteger method, of class Owasp.Esapi.Randomizer.</summary>
        [Test]
        public void Test_GetRandomInteger()
        {
            System.Console.Out.WriteLine("GetRandomInteger");
            int min = -20;
            int max = 100;
            IRandomizer randomizer = Esapi.Randomizer();
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

        /// <summary> Test of GetRandomReal method, of class Owasp.Esapi.Randomizer.</summary>
        [Test]
        public void Test_GetRandomReal()
        {
            System.Console.Out.WriteLine("GetRandomReal");
            float min = -20.5234F;
            float max = 100.12124F;
            IRandomizer randomizer = Esapi.Randomizer();
            float minResult = (max - min) / 2;
            float maxResult = (max - min) / 2;
            for (int i = 0; i < 100; i++)
            {
                float result = randomizer.GetRandomReal(min, max);
                if (result < minResult)
                    minResult = result;
                if (result > maxResult)
                    maxResult = result;
            }
            Assert.AreEqual(true, (minResult >= min && maxResult < max));
        }


        /// <summary> Test of GetRandomGUID method, of class Owasp.Esapi.Randomizer.</summary>
        [Test]
        public void Test_GetRandomGUID()
        {
            System.Console.Out.WriteLine("GetRandomGUID");
            IRandomizer randomizer = Esapi.Randomizer();
            ArrayList list = new ArrayList();
            for (int i = 0; i < 100; i++)
            {
                string guid = randomizer.RandomGUID;
                if (list.Contains(guid))
                    Assert.Fail();
                list.Add(guid);
            }
        }
    }
}
