/// <summary> OWASP Enterprise Security API .NET  = Esapi.NET) 
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
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Test.Http;

namespace Owasp.Esapi.Test
{

    /// <summary> The Class EsapiTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class EsapiTest
    {

        /**
         * Test of all the ESAPI setter methods
         * 
         * @throws Exception
         *             the exception
         */
        [Test]
        public void Test_Setters()
        {
            Console.Out.WriteLine("Test_Setters");
            // TODO - Need to make the Esapi class have settable properties. Going to change all of these methods to properties.
            //Esapi.AccessController = Esapi.AccessController();
            //Esapi.Authenticator = Esapi.Authenticator();
            //Esapi.Encoder = Esapi.Encoder();
            //Esapi.Encryptor = Esapi.Encryptor();
            //Esapi.Executor = Esapi.Executor();
            //Esapi.HttpUtilities = Esapi.HttpUtilities();
            //Esapi.IntrusionDetector = Esapi.IntrusionDetector();
            //Esapi.Randomizer = Esapi.Randomizer();
            //Esapi.SecurityConfiguration = Esapi.SecurityConfiguration();
            //Esapi.Validator = Esapi.Validator();
        }
    }
}
