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
/// 
using System;
using NUnit.Framework;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Test.Http;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class IntrusionDetectorTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class IntrusionDetectorTest
    {
        /// <summary> Instantiates a new intrusion detector test.
        /// 
        /// </summary>
        public IntrusionDetectorTest():this(null)
        {
        }
                
        /// <summary> Instantiates a new intrusion detector test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public IntrusionDetectorTest(string testName)
        {
        }
        /// <summary> Test of AddException method, of class Owasp.Esapi.IntrusionDetector.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_AddException()
        {
            System.Console.Out.WriteLine("AddException");
            Esapi.IntrusionDetector().AddException(new IntrusionException("user message", "log message"));
            IUser user = Esapi.Authenticator().GetUser("AddException");
            if (user != null)
            {
                Esapi.Authenticator().RemoveUser("AddException");
            }
            user = Esapi.Authenticator().CreateUser("AddException", "AddException", "AddException");
            ((Authenticator)Esapi.Authenticator()).Context = new MockHttpContext();
            Esapi.Authenticator().SetCurrentUser(user);
            
            user.Enable();

            // Now generate some exceptions to disable account
            for (int i = 0; i < Esapi.SecurityConfiguration().GetQuota("Owasp.Esapi.Errors.ValidationException").Count; i++)
            {
                // EnterpriseSecurityExceptions are added to IntrusionDetector automatically
                new ValidationException("ValidationException " + i, "ValidationException " + i);
            }
            Assert.IsFalse(user.Enabled);            
        }


        /// <summary> Test of AddEvent method, of class Owasp.Esapi.IntrusionDetector.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_AddEvent()
        {
            System.Console.Out.WriteLine("AddEvent");
            IUser user = Esapi.Authenticator().GetUser("AddEvent");
            if (user != null)
            {
                Esapi.Authenticator().RemoveUser("AddEvent");
            }
            user = Esapi.Authenticator().CreateUser("AddEvent", "AddEvent", "AddEvent");
            ((Authenticator)Esapi.Authenticator()).Context = new MockHttpContext();
            Esapi.Authenticator().SetCurrentUser(user);
            user.Enable();

            // Now generate some events to disable user account
            for (int i = 0; i < Esapi.SecurityConfiguration().GetQuota("event.test").Count; i++)
            {
                Esapi.IntrusionDetector().AddEvent("test");
            }
            Assert.IsFalse(user.Enabled);            
        }
    }
}
