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
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Test.Http;

namespace Owasp.Esapi.Test
{

    /// <summary> The Class AccessControllerTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class AccessControllerTest
    {
        /// <summary> Initializes a new access controller test.
		/// 
		/// </summary>		
        [SetUp]
		public void Init()
		{
            IAuthenticator authenticator = Esapi.Authenticator();
            ((Authenticator) authenticator).Context = new MockHttpContext();
			IEnumerator i = authenticator.GetUserNames().GetEnumerator();			
			while (i.MoveNext())
			{			
				String name = (String) i.Current;
				authenticator.RemoveUser(name);
			}
			String password = authenticator.GenerateStrongPassword();			
			// create a user with the "user" role for this test
			IUser alice =  authenticator.CreateUser("testuser1", password, password);
			alice.AddRole("user");
			authenticator.SetCurrentUser(alice);
			
			// create a user with the "admin" role for this test
			IUser bob = authenticator.CreateUser("testuser2", password, password);
			bob.AddRole("admin");
			authenticator.SetCurrentUser(bob);
			
			// create a user with the "user" and "admin" roles for this test
			IUser mitch = authenticator.CreateUser("testuser3", password, password);
			mitch.AddRole("admin");
			mitch.AddRole("user");
			authenticator.SetCurrentUser(mitch);
		}

        /// <summary> Test of IsAuthorizedForURL method, of class
		/// Owasp.Esapi.AccessController.
		/// </summary>
		[Test]
        public void Test_IsAuthorizedForURL()
		{
			System.Console.Out.WriteLine("IsAuthorizedForURL");
			IAccessController accessController = Owasp.Esapi.Esapi.AccessController();
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser1"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/nobody"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/test/admin"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/user"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/all"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/test/none"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/none/test.gif"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/test/none/test.exe"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser2"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/nobody"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/admin"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/test/user"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/all"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/test/none"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser3"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/nobody"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/admin"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/user"));
			Assert.IsTrue(accessController.IsAuthorizedForUrl("/test/all"));
			Assert.IsFalse(accessController.IsAuthorizedForUrl("/test/none"));

            try
            {
                accessController.AssertAuthorizedForUrl("/test/admin");
                accessController.AssertAuthorizedForUrl("/nobody");
                Assert.Fail("Expection expected when user attempting to access unauthorized URL.");
            }
            catch (AccessControlException e)
            {
                // expected
            }

            
		}
		
		/// <summary> Test of IsAuthorizedForFunction method, of class
		/// Owasp.Esapi.AccessController.
		/// </summary>        
        [Test]
		public void Test_IsAuthorizedForFunction()
		{
			System.Console.Out.WriteLine("isAuthorizedForFunction");
			IAccessController accessController = Esapi.AccessController();
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser1"));
			Assert.IsTrue(accessController.IsAuthorizedForFunction("/FunctionA"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionAdeny"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionB"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionBdeny"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser2"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionA"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionAdeny"));
			Assert.IsTrue(accessController.IsAuthorizedForFunction("/FunctionB"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionBdeny"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser3"));
			Assert.IsTrue(accessController.IsAuthorizedForFunction("/FunctionA"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionAdeny"));
			Assert.IsTrue(accessController.IsAuthorizedForFunction("/FunctionB"));
			Assert.IsFalse(accessController.IsAuthorizedForFunction("/FunctionBdeny"));

            try
            {
                accessController.AssertAuthorizedForFunction("/FunctionA");
                accessController.AssertAuthorizedForFunction("/FunctionAdeny");
                Assert.Fail("Expection expected when user attempting to access unauthorized function.");
            }
            catch (AccessControlException e)
            {
                // expected
            }

		}
		
		/// <summary> Test of IsAuthorizedForData method, of class
		/// Owasp.Esapi.AccessController.
		/// </summary>		
        [Test]
        public void Test_IsAuthorizedForData()
		{
			System.Console.Out.WriteLine("isAuthorizedForData");
			IAccessController accessController = Esapi.AccessController();
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser1"));
			Assert.IsTrue(accessController.IsAuthorizedForData("/Data1"));
			Assert.IsFalse(accessController.IsAuthorizedForData("/Data2"));
			Assert.IsFalse(accessController.IsAuthorizedForData("/not_listed"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser2"));
			Assert.IsFalse(accessController.IsAuthorizedForData("/Data1"));
			Assert.IsTrue(accessController.IsAuthorizedForData("/Data2"));
			Assert.IsFalse(accessController.IsAuthorizedForData("/not_listed"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser3"));
			Assert.IsTrue(accessController.IsAuthorizedForData("/Data1"));
			Assert.IsTrue(accessController.IsAuthorizedForData("/Data2"));
			Assert.IsFalse(accessController.IsAuthorizedForData("/not_listed"));

            try
            {
                accessController.AssertAuthorizedForData("/Data1");
                accessController.AssertAuthorizedForData("/not_listed");
                Assert.Fail("Expection expected when user attempting to access unauthorized data.");
            }
            catch (AccessControlException e)
            {
                // expected
            }

		    
		}
		
		/// <summary> Test of IsAuthorizedForFile method, of class
		/// Owasp.Esapi.AccessController.
		/// </summary>
        
        [Test]
		public void Test_IsAuthorizedForFile()
		{
			System.Console.Out.WriteLine("isAuthorizedForFile");
			IAccessController accessController = Esapi.AccessController();
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser1"));
			Assert.IsTrue(accessController.IsAuthorizedForFile("/Dir/File1"));
			Assert.IsFalse(accessController.IsAuthorizedForFile("/Dir/File2"));
			Assert.IsFalse(accessController.IsAuthorizedForFile("/Dir/ridiculous"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser2"));
			Assert.IsFalse(accessController.IsAuthorizedForFile("/Dir/File1"));
			Assert.IsTrue(accessController.IsAuthorizedForFile("/Dir/File2"));
			Assert.IsFalse(accessController.IsAuthorizedForFile("/Dir/ridiculous"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser3"));
			Assert.IsTrue(accessController.IsAuthorizedForFile("/Dir/File1"));
			Assert.IsTrue(accessController.IsAuthorizedForFile("/Dir/File2"));
			Assert.IsFalse(accessController.IsAuthorizedForFile("/Dir/ridiculous"));

            try
            {
                accessController.AssertAuthorizedForFile("/Dir/File1");
                accessController.AssertAuthorizedForFile("/Dir/ridiculous");
                Assert.Fail("Expection expected when user attempting to access unauthorized file.");
            }
            catch (AccessControlException e)
            {
                // expected
            }

		}
		
		/// <summary> Test of IsAuthorizedForBackendService method, of class
		/// Owasp.Esapi.AccessController.
		/// </summary>
		
        [Test]
        public void Test_IsAuthorizedForBackendService()
		{
			System.Console.Out.WriteLine("isAuthorizedForBackendService");
			IAccessController accessController = Esapi.AccessController();
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser1"));
			Assert.IsTrue(accessController.IsAuthorizedForService("/services/ServiceA"));
			Assert.IsFalse(accessController.IsAuthorizedForService("/services/ServiceB"));
			Assert.IsFalse(accessController.IsAuthorizedForService("/test/ridiculous"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser2"));
			Assert.IsFalse(accessController.IsAuthorizedForService("/services/ServiceA"));
			Assert.IsTrue(accessController.IsAuthorizedForService("/services/ServiceB"));
			Assert.IsFalse(accessController.IsAuthorizedForService("/test/ridiculous"));
			
			Esapi.Authenticator().SetCurrentUser(Esapi.Authenticator().GetUser("testuser3"));
			Assert.IsTrue(accessController.IsAuthorizedForService("/services/ServiceA"));
			Assert.IsTrue(accessController.IsAuthorizedForService("/services/ServiceB"));
			Assert.IsFalse(accessController.IsAuthorizedForService("/test/ridiculous"));

            try
            {
                accessController.AssertAuthorizedForService("/services/ServiceA");
                accessController.AssertAuthorizedForService("/test/ridiculous");
                Assert.Fail("Expection expected when user attempting to access unauthorized backend service.");
            }
            catch (AccessControlException e)
            {
                // expected
            }

		    
		}
        public void testMatchRule()
        {
            Esapi.Authenticator().SetCurrentUser(null);
            Assert.IsFalse(Esapi.AccessController().IsAuthorizedForUrl("/nobody"));
        }
    }
}
