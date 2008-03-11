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
using Owasp.Esapi.Errors;

namespace Owasp.Esapi.Test.Errors
{
    [TestFixture]
    public class EnterpriseSecurityExceptionTest
    {

        /// <summary> Instantiates a new enterprise security exception test.
        /// 
        /// </summary>
        public EnterpriseSecurityExceptionTest():this(null)
        {
        }

        /// <summary> Instantiates a new enterprise security exception test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public EnterpriseSecurityExceptionTest(string testName)            
        {
        }


        /// <summary> Test of Exceptions, from Owasp.Espai.Errors
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void TestExceptions()
        {
            System.Console.Out.WriteLine("exceptions");
            EnterpriseSecurityException e = null;
            //e = new EnterpriseSecurityException();
            e = new EnterpriseSecurityException("m1", "m2");
            
            e = new EnterpriseSecurityException("m1", "m2", new System.Exception());
            Assert.AreEqual(e.UserMessage, "m1");
            Assert.AreEqual(e.LogMessage, "m2");
            //e = new AccessControlException();
            e = new AccessControlException("m1", "m2");
            
            e = new AccessControlException("m1", "m2", new System.Exception());
            //e = new AuthenticationException();
            e = new AuthenticationException("m1", "m2");
            
            e = new AuthenticationException("m1", "m2", new System.Exception());
            //e = new AvailabilityException();
            e = new AvailabilityException("m1", "m2");
            
            e = new AvailabilityException("m1", "m2", new System.Exception());
            //e = new CertificateException();
            e = new CertificateException("m1", "m2");
            
            e = new CertificateException("m1", "m2", new System.Exception());
            //e = new EncodingException();
            e = new EncodingException("m1", "m2");
            
            e = new EncodingException("m1", "m2", new System.Exception());
            //e = new EncryptionException();
            e = new EncryptionException("m1", "m2");
            
            e = new EncryptionException("m1", "m2", new System.Exception());
            //e = new ExecutorException();
            e = new ExecutorException("m1", "m2");
            
            e = new ExecutorException("m1", "m2", new System.Exception());
            //e = new ValidationException();
            e = new ValidationException("m1", "m2");
            
            e = new ValidationException("m1", "m2", new System.Exception());

            //e = new AuthenticationAccountsException();
            e = new AuthenticationAccountsException("m1", "m2");
            
            e = new AuthenticationAccountsException("m1", "m2", new System.Exception());
            //e = new AuthenticationCredentialsException();
            e = new AuthenticationCredentialsException("m1", "m2");
            
            e = new AuthenticationCredentialsException("m1", "m2", new System.Exception());
           // e = new AuthenticationLoginException();
            e = new AuthenticationLoginException("m1", "m2");
            
            e = new AuthenticationLoginException("m1", "m2", new System.Exception());
            //e = new ValidationAvailabilityException();
            e = new ValidationAvailabilityException("m1", "m2");
            
            e = new ValidationAvailabilityException("m1", "m2", new System.Exception());
            //e = new ValidationUploadException();
            e = new ValidationUploadException("m1", "m2");
            
            e = new ValidationUploadException("m1", "m2", new System.Exception());

            IntrusionException ex = new IntrusionException();
            ex = new IntrusionException("m1", "m2");
            
            ex = new IntrusionException("m1", "m2", new System.Exception());
            Assert.AreEqual(ex.UserMessage, "m1");
            Assert.AreEqual(ex.LogMessage, "m2");
        }
    }


}
