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
using Owasp.Esapi.Test.Http;
using HttpInterfaces;
using System.Collections;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class LoggerTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class LoggerTest
    {

        private static readonly ILogger logger = Esapi.Logger();
        
        /// <summary> Instantiates a new logger test.
        /// 
        /// </summary>
        public LoggerTest():this(null)
        {
        }

        /// <summary> Instantiates a new logger test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public LoggerTest(string testName)
        {
        }


        /// <summary> Test of LogHTTPRequest method, of class Owasp.Esapi.Logger.
        /// 
        /// </summary>
        /// <throws>  ValidationException </throws>
        /// <summary>             the validation exception
        /// </summary>
        /// <throws>  IOException </throws>
        /// <summary>             Signals that an I/O exception has occurred.
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_LogHTTPRequest()
        {
            System.Console.Out.WriteLine("LogHTTPRequest");
            string[] ignore = new string[] { "password" };            
            MockHttpContext context = new MockHttpContext();
            ((Authenticator)Esapi.Authenticator()).Context = context;
            IHttpRequest request = context.Request;
            Esapi.HttpUtilities().LogHttpRequest(new ArrayList(ignore));
            request.Params.Add("one", "one");
            request.Params.Add("two", "two1");
            request.Params.Add("two", "two2");
            request.Params.Add("password", "jwilliams");
            Esapi.HttpUtilities().LogHttpRequest(new ArrayList(ignore));
        }

        /// <summary> Test of Info method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_Info()
        {
            System.Console.Out.WriteLine("Info");
            logger.Info(LogEventTypes.SECURITY, "test message");
            logger.Info(LogEventTypes.SECURITY, "test message", null);
            logger.Info(LogEventTypes.SECURITY, "%3escript%3f test message", null);
            logger.Info(LogEventTypes.SECURITY, "<script> test message", null);
        }


        /// <summary> Test of Trace method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_Trace()
        {
            System.Console.Out.WriteLine("Trace");
            logger.Trace(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message");
            logger.Trace(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message", null);
        }

        /// <summary> Test of LogDebug method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_LogDebug()
        {
            System.Console.Out.WriteLine("logDebug");
            logger.Debug(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message");
            logger.Debug(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message", null);
        }

        /// <summary> Test of Error method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_Error()
        {
            System.Console.Out.WriteLine("Error");
            logger.Error(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message");
            logger.Error(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message", null);
        }

        /// <summary> Test of Warning method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_Warning()
        {
            System.Console.Out.WriteLine("Warning");
            logger.Warning(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message");
            logger.Warning(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message", null);
        }

        /// <summary> Test of Fatal method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_Fatal()
        {
            System.Console.Out.WriteLine("Fatal");
            logger.Fatal(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message");
            logger.Fatal(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "test message", null);
        }
    }
}
