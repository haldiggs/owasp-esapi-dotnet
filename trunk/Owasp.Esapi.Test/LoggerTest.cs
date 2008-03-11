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
using Owasp.Esapi.Test.Http;
using HttpInterfaces;
using System.Collections;

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
            IHttpRequest request = context.Request;            
            Logger.GetLogger("logger", "logger").LogHttpRequest(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, request, new ArrayList(ignore));
            request.Params.Add("one", "one");
            request.Params.Add("two", "two1");
            request.Params.Add("two", "two2");
            request.Params.Add("password", "jwilliams");
            Logger.GetLogger("logger", "logger").LogHttpRequest(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, request, new ArrayList(ignore));
        }

        /// <summary> Test of LogSuccess method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_LogSuccess()
        {
            System.Console.Out.WriteLine("LogSuccess");
            Logger.GetLogger("app", "mod").LogSuccess(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message");
            Logger.GetLogger("app", "mod").LogSuccess(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message", null);
            Logger.GetLogger("app", "mod").LogSuccess(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "%3escript%3f test message", null);
            Logger.GetLogger("app", "mod").LogSuccess(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "<script> test message", null);
        }


        /// <summary> Test of LogTrace method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_LogTrace()
        {
            System.Console.Out.WriteLine("LogTrace");
            Logger.GetLogger("app", "mod").LogTrace(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message");
            Logger.GetLogger("app", "mod").LogTrace(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message", null);
        }

        /// <summary> Test of LogDebug method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_LogDebug()
        {
            System.Console.Out.WriteLine("logDebug");
            Logger.GetLogger("app", "mod").LogDebug(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message");
            Logger.GetLogger("app", "mod").LogDebug(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message", null);
        }

        /// <summary> Test of LogError method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_LogError()
        {
            System.Console.Out.WriteLine("logError");
            Logger.GetLogger("app", "mod").LogError(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message");
            Logger.GetLogger("app", "mod").LogError(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message", null);
        }

        /// <summary> Test of LogWarning method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_LogWarning()
        {
            System.Console.Out.WriteLine("LogWarning");
            Logger.GetLogger("app", "mod").LogWarning(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message");
            Logger.GetLogger("app", "mod").LogWarning(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message", null);
        }

        /// <summary> Test of LogCritical method, of class Owasp.Esapi.Logger.</summary>
        [Test]
        public void Test_LogCritical()
        {
            System.Console.Out.WriteLine("LogCritical");
            Logger.GetLogger("app", "mod").LogCritical(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message");
            Logger.GetLogger("app", "mod").LogCritical(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "test message", null);
        }
    }
}
