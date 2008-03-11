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
using Owasp.Esapi.Test.Http;
using System.Threading;
using HttpInterfaces;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Test
{

    /// <summary> The Class AuthenticatorTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class AuthenticatorTest
    {       
        private class GetCurrentUserRunnable
        {
            public bool Result
            {
                get
                {
                    return result;
                }

            }
            private static int count = 1;
            private static bool result = false;
            public static void Run()
            {
                IAuthenticator authenticator = Esapi.Authenticator();
                IUser a = null;
                try
                {
                    String password = authenticator.GenerateStrongPassword();
                    String accountName = "TestAccount" + count++;
                    a = authenticator.GetUser(accountName);
                    if (a != null)
                    {
                        authenticator.RemoveUser(accountName);
                    }
                    a = authenticator.CreateUser(accountName, password, password);
                    authenticator.SetCurrentUser(a);
                }
                catch (AuthenticationException e)
                {
                    System.Console.Out.WriteLine(e.StackTrace);
                }
                IUser b = authenticator.GetCurrentUser();
                result &= a.Equals(b);
            }
        }

        
        private class SetCurrentUserRunnable
        {
            private int count = 1;
            public virtual void Run()
            {
                IUser u = null;
                try
                {
                    String password = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
                    u = Esapi.Authenticator().CreateUser("test" + count++, password, password);
                }
                catch (AuthenticationException e)
                {
                    System.Console.Out.WriteLine(e.StackTrace);
                }
                Esapi.Authenticator().SetCurrentUser(u);
                Logger.GetLogger("test", "test").LogCritical(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "Got current user");
            }
        }

        /// <summary> Instantiates a new authenticator test.
        /// 
        /// </summary>
        public AuthenticatorTest():this(null)
        {
        }

        /// <summary> Instantiates a new authenticator test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public AuthenticatorTest(String testName)
        {
        }


        /// <summary> Test of CreateUser method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>        
        [Test]
        public void Test_CreateUser()
        {
            System.Console.Out.WriteLine("CreateUser");
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            IUser user = authenticator.CreateUser(accountName, password, password);
            Assert.IsTrue(user.VerifyPassword(password));
            try
            {
                authenticator.CreateUser(accountName, password, password); // duplicate user
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.CreateUser(Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS), "password1", "password2"); // don't match
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.CreateUser(Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS), "weak1", "weak1"); // weak password
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.CreateUser(null, "weak1", "weak1"); // null username
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.CreateUser(Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS), null, null); // null password
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
        }

        /// <summary> Test of GenerateStrongPassword method, of class
        /// Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_GenerateStrongPassword()
        {
            System.Console.Out.WriteLine("GenerateStrongPassword");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            for (int i = 0; i < 100; i++)
            {
                try
                {
                    string newPassword = authenticator.GenerateStrongPassword();
                    authenticator.VerifyPasswordStrength(newPassword, oldPassword);
                }
                catch (AuthenticationException e)
                {
                    Assert.Fail();
                }
            }
        }


        /// <summary> Test of GetCurrentUser method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  InterruptedException * </throws>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_GetCurrentUser()
        {
            System.Console.Out.WriteLine("GetCurrentUser");
            IAuthenticator authenticator = Esapi.Authenticator();
            string username1 = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            string username2 = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            IUser user1 = authenticator.CreateUser(username1, "GetCurrentUser", "GetCurrentUser");
            IUser user2 = authenticator.CreateUser(username2, "GetCurrentUser", "GetCurrentUser");
            user1.Enable();
            
            MockHttpContext context = new MockHttpContext();                        
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            ((Authenticator)authenticator).Context = context;
            user1.LoginWithPassword("GetCurrentUser");
            IUser currentUser = authenticator.GetCurrentUser();
            Assert.AreEqual(currentUser, user1);
            authenticator.SetCurrentUser(user2);
            Assert.IsFalse(currentUser.AccountName.Equals(user2.AccountName));            
            
            // There is no equivalent in C# of a ThreadGroup in Java. What's the point
            // of this test? To test the effects of multithreading? Will have to follow
            // up with Jeff.

            ThreadStart echo = new ThreadStart(GetCurrentUserRunnable.Run);
            for (int i = 0; i < 10; i++)
            {
                new Thread(echo).Start();
            }            
            //while (tg.activeCount() > 0)
            //{                
            //    System.Threading.Thread.Sleep(new System.TimeSpan((System.Int64)10000 * 100));
            //}
            // FIXME: AAA need a way to get results here from runnables
        }

        /// <summary> Test of GetUser method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_GetUser()
        {
            System.Console.Out.WriteLine("GetUser");
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            authenticator.CreateUser(accountName, password, password);
            Assert.IsNotNull(authenticator.GetUser(accountName));
            Assert.IsNull(authenticator.GetUser(Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS)));
        }

        /// <summary> Test get user from session.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_GetUserFromSession()
        {
            System.Console.Out.WriteLine("GetUserFromSession");
            IAuthenticator authenticator = Esapi.Authenticator();
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            string password = authenticator.GenerateStrongPassword();
            IUser user = authenticator.CreateUser(accountName, password, password);
            user.Enable();
                        
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            request.Params.Add("username", accountName);
            request.Params.Add("password", password);
            ((Authenticator)authenticator).Context = context;
            authenticator.Login();
            IUser test = authenticator.GetUserFromSession(request);
            Assert.AreEqual(user, test);
        }

        /// <summary> Test get user names.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_GetUserNames()
        {
            System.Console.Out.WriteLine("GetUserNames");
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            string[] testnames = new string[] { "firstUser", "secondUser", "thirdUser" };
            for (int i = 0; i < testnames.Length; i++)
            {
                authenticator.CreateUser(testnames[i], password, password);
            }
            IList names = authenticator.GetUserNames();
            for (int i = 0; i < testnames.Length; i++)
            {
                Assert.IsTrue(names.Contains(testnames[i].ToLower()));
            }
        }

        /// <summary> Test of hashPassword method, of class Owasp.Esapi.Authenticator.</summary>
        [Test]
        public void Test_HashPassword()
        {
            System.Console.Out.WriteLine("HashPassword");
            string username = "Alex";
            string password = "test";
            IAuthenticator authenticator = Esapi.Authenticator();
            string result1 = authenticator.HashPassword(password, username);
            string result2 = authenticator.HashPassword(password, username);
            Assert.IsTrue(result1.Equals(result2));
        }

        /// <summary> Test of login method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_Login()
        {
            System.Console.Out.WriteLine("Login");
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            IUser user = authenticator.CreateUser("login", password, password);
            user.Enable();
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            request.Params.Add("username", "login");
            request.Params.Add("password", password);
            ((Authenticator) authenticator).Context = context;
            IUser test = authenticator.Login();
            Assert.IsTrue(test.LoggedIn);
        }

        /// <summary> Test of RemoveUser method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_RemoveUser()
        {
            System.Console.Out.WriteLine("RemoveUser");
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            authenticator.CreateUser(accountName, password, password);
            Assert.IsTrue(authenticator.Exists(accountName));
            authenticator.RemoveUser(accountName);
            Assert.IsFalse(authenticator.Exists(accountName));
            IEnumerator i = authenticator.GetUserNames().GetEnumerator();            
            while (i.MoveNext())
            {                
                string name = (string)i.Current;
                authenticator.RemoveUser(name);
            }
        }

        /// <summary> Test of SaveUsers method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_SaveUsers()
        {
            System.Console.Out.WriteLine("SaveUsers");
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            Authenticator authenticator = (Authenticator) Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            authenticator.CreateUser(accountName, password, password);
            authenticator.SaveUsers();
            Assert.IsNotNull(authenticator.GetUser(accountName));
            authenticator.RemoveUser(accountName);
            Assert.IsNull(authenticator.GetUser(accountName));
        }


        /// <summary> Test of SetCurrentUser method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_SetCurrentUser()
        {
            System.Console.Out.WriteLine("SetCurrentUser");
            string user1 = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_UPPERS);
            string user2 = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_UPPERS);
            IUser userOne = Esapi.Authenticator().CreateUser(user1, "GetCurrentUser", "GetCurrentUser");
            userOne.Enable();
            IAuthenticator authenticator = Esapi.Authenticator();            
            MockHttpContext context = new MockHttpContext();
            ((Authenticator)authenticator).Context = context;
            userOne.LoginWithPassword("GetCurrentUser");
            IUser currentUser = authenticator.GetCurrentUser();
            Assert.AreEqual(currentUser, userOne);
            IUser userTwo = authenticator.CreateUser(user2, "GetCurrentUser", "GetCurrentUser");
            authenticator.SetCurrentUser(userTwo);
            Assert.IsFalse(currentUser.AccountName.Equals(userTwo.AccountName));

            ThreadStart echo = new ThreadStart(GetCurrentUserRunnable.Run);
            for (int i = 0; i < 10; i++)
            {
                new Thread(echo).Start();
            }
        }


        /// <summary> Test of SetCurrentUser method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_SetCurrentUserWithRequest()
        {
            System.Console.Out.WriteLine("SetCurrentUser(req,resp)");
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            String accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            IUser user = authenticator.CreateUser(accountName, password, password);
            user.Enable();
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            request.Params.Add("username", accountName);
            request.Params.Add("password", password);
            ((Authenticator) authenticator).Context = context;
            authenticator.Login();
            Assert.AreEqual(user, authenticator.GetCurrentUser());
            try
            {
                user.Disable();              
                authenticator.Login();
            }
            catch (Exception e)
            {
                // expected
            }
            try
            {
                user.Enable();
                user.Lock();
                authenticator.Login();
            }
            catch (System.Exception e)
            {
                // expected
            }
            try
            {
                user.Unlock();
                user.ExpirationTime = System.DateTime.Now;
                authenticator.Login();
            }
            catch (System.Exception e)
            {
                // expected
            }
        }



        /// <summary> Test of ValidatePasswordStrength method, of class
        /// Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public virtual void Test_ValidatePasswordStrength()
        {
            System.Console.Out.WriteLine("validatePasswordStrength");
            IAuthenticator authenticator = Esapi.Authenticator();

            // should fail
            try
            {
                authenticator.VerifyPasswordStrength("alex", "password");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.VerifyPasswordStrength("same123string", "diff123bang");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.VerifyPasswordStrength("alex", "password");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.VerifyPasswordStrength("1234", "password");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.VerifyPasswordStrength("password", "password");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.VerifyPasswordStrength("-1", "password");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.VerifyPasswordStrength("password123", "password");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }
            try
            {
                authenticator.VerifyPasswordStrength("test123", "password");
                Assert.Fail();
            }
            catch (AuthenticationException e)
            {
                // success
            }

            // should pass
            authenticator.VerifyPasswordStrength("alexALEX12!", "password");
            authenticator.VerifyPasswordStrength("super calif ragil istic", "password");
            authenticator.VerifyPasswordStrength("TONYTONYTONYTONY", "password");
            authenticator.VerifyPasswordStrength(authenticator.GenerateStrongPassword(), "password");
        }

        /// <summary> Test of Exists method, of class Owasp.Esapi.Authenticator.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_Exists()
        {
            System.Console.Out.WriteLine("exists");
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            authenticator.CreateUser(accountName, password, password);
            Assert.IsTrue(authenticator.Exists(accountName));
            authenticator.RemoveUser(accountName);
            Assert.IsFalse(authenticator.Exists(accountName));
        }

        /// <summary> Test of Main method, of class Owasp.Esapi.Authenticator.</summary>
        [Test]
        public void Test_Main()
        {
            System.Console.Out.WriteLine("authenticator");
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            string password = Esapi.Authenticator().GenerateStrongPassword();
            string role = "test";
            // test wrong parameters
            string[] badArgs = new string[] { accountName, password };
            
            Authenticator.Main(badArgs);
            IUser u1 = Esapi.Authenticator().GetUser(accountName);
            Assert.IsNull(u1);
            // test good parameters
            string[] args = new string[] { accountName, password, role };
            Authenticator.Main(args);
            User u2 = (User) Esapi.Authenticator().GetUser(accountName);
            Assert.IsNotNull(u2);
            Assert.IsTrue(u2.IsInRole(role));
            Assert.AreEqual(Esapi.Authenticator().HashPassword(password, accountName), u2.GetHashedPassword());
        }
    }
}
