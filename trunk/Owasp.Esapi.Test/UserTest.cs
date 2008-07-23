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
using System.Threading;
using HttpInterfaces;
using Owasp.Esapi.Test.Http;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class UserTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class UserTest
    {

        /// <summary> Instantiates a new user test.
        /// 
        /// </summary>
        public UserTest():this(null)
        {

        }
        
        /// <summary> Instantiates a new user test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public UserTest(string testName)
        {

        }
        /// <summary> Creates the test user.
        /// 
        /// </summary>
        /// <param name="password">the password
        /// 
        /// </param>
        /// <returns> the user
        /// 
        /// </returns>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        private User CreateTestUser(string password)
        {
            string username = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            User user = (User) Esapi.Authenticator().CreateUser(username, password, password);
            return user;
        }

        /// <summary> Test of TestAddRole method, of class Owasp.Esapi.User.</summary>
        [Test]
        public void Test_AddRole()
        {
            System.Console.Out.WriteLine("AddRole");
            IAuthenticator authenticator = Esapi.Authenticator();
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            string password = Esapi.Authenticator().GenerateStrongPassword();
            string role = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_LOWERS);
            User user = (User) authenticator.CreateUser(accountName, password, password);
            user.AddRole(role);
            Assert.IsTrue(user.IsInRole(role));
            Assert.IsFalse(user.IsInRole("ridiculous"));
        }

        /// <summary> Test of AddRoles method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_AddRoles()
        {
            System.Console.Out.WriteLine("AddRoles");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);            
            ArrayList roles = new ArrayList();
            roles.Add("rolea");
            roles.Add("roleb");
            user.AddRoles(roles);
            Assert.IsTrue(user.IsInRole("rolea"));
            Assert.IsTrue(user.IsInRole("roleb"));
            Assert.IsFalse(user.IsInRole("ridiculous"));
        }

        /// <summary> Test of ChangePassword method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_ChangePassword()
        {
            System.Console.Out.WriteLine("ChangePassword");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            string password1 = authenticator.GenerateStrongPassword();
            user.ChangePassword(oldPassword, password1, password1);
            Assert.IsTrue(user.VerifyPassword(password1));
            string password2 = authenticator.GenerateStrongPassword();
            user.ChangePassword(password1, password2, password2);
            try
            {
                user.ChangePassword(password2, password1, password1);
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            Assert.IsTrue(user.VerifyPassword(password2));
            Assert.IsFalse(user.VerifyPassword("badpass"));
        }

        /// <summary> Test of Disable method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_Disable()
        {
            System.Console.Out.WriteLine("disable");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            user.Enable();
            Assert.IsTrue(user.Enabled);
            user.Disable();
            Assert.IsFalse(user.Enabled);
        }

        /// <summary> Test of Enable method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_Enable()
        {
            System.Console.Out.WriteLine("enable");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            user.Enable();
            Assert.IsTrue(user.Enabled);
            user.Disable();
            Assert.IsFalse(user.Enabled);
        }

        /// <summary> Test equals.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_Equals()
        {
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            User a = new User("userA", password, password);
            User b = new User("userA", "differentPass", "differentPass");
            a.Enable();
            Assert.IsTrue(a.Equals(b));
        }

        /// <summary> Test of FailedLoginCount lockout, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_FailedLoginLockout()
        {
            System.Console.Out.WriteLine("failedLoginLockout");
            IAuthenticator authenticator = Esapi.Authenticator();
            User user = CreateTestUser("failedLoginLockout");
            string password = authenticator.GenerateStrongPassword();
            user.Unlock();
            user.ChangePassword("failedLoginLockout", password, password);
            user.VerifyPassword(password);
            user.VerifyPassword("ridiculous");
            System.Console.Out.WriteLine("FAILED: " + user.FailedLoginCount);
            Assert.IsFalse(user.Locked);
            user.VerifyPassword("ridiculous");
            System.Console.Out.WriteLine("FAILED: " + user.FailedLoginCount);
            Assert.IsFalse(user.Locked);
            user.VerifyPassword("ridiculous");
            System.Console.Out.WriteLine("FAILED: " + user.FailedLoginCount);
            Assert.IsTrue(user.Locked);
        }

        /// <summary> Test of GetAccountName method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_GetAccountName()
        {
            System.Console.Out.WriteLine("GetAccountName");
            User user = CreateTestUser("GetAccountName");
            string accountName = Esapi.Randomizer().GetRandomString(7, Encoder.CHAR_ALPHANUMERICS);
            user.AccountName = accountName;
            Assert.AreEqual(accountName.ToLower(), user.AccountName);
            Assert.IsFalse("ridiculous".Equals(user.AccountName));
        }

        /// <summary> Test get last failed login time.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_GetLastFailedLoginTime()
        {
            System.Console.Out.WriteLine("GetLastLoginTime");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            user.VerifyPassword("ridiculous");
            System.DateTime llt1 = user.GetLastFailedLoginTime();            
            Thread.Sleep(new TimeSpan((System.Int64)10000 * 10)); // need a short delay to separate attempts
            user.VerifyPassword("ridiculous");
            System.DateTime llt2 = user.GetLastFailedLoginTime();
            Assert.IsTrue((llt1 < llt2));
        }

        /// <summary> Test get last login time.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_GetLastLoginTime()
        {
            System.Console.Out.WriteLine("GetLastLoginTime");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            user.VerifyPassword(oldPassword);
            System.DateTime llt1 = user.GetLastLoginTime();            
            Thread.Sleep(new TimeSpan((System.Int64)10000 * 10)); // need a short delay to separate attempts
            user.VerifyPassword(oldPassword);
            System.DateTime llt2 = user.GetLastLoginTime();
            Assert.IsTrue((llt1 < llt2));
        }

        /// <summary> Test of GetLastPasswordChangeTime method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_GetLastPasswordChangeTime()
        {
            System.Console.Out.WriteLine("GetLastPasswordChangeTime");
            User user = CreateTestUser("GetLastPasswordChangeTime");
            System.DateTime t1 = user.GetLastPasswordChangeTime();            
            Thread.Sleep(new TimeSpan((System.Int64)10000 * 10)); // need a short delay to separate attempts
            string newPassword = Esapi.Authenticator().GenerateStrongPassword("GetLastPasswordChangeTime", user);
            user.ChangePassword("GetLastPasswordChangeTime", newPassword, newPassword);
            System.DateTime t2 = user.GetLastPasswordChangeTime();
            Assert.IsTrue((t2 > t1));
        }

        /// <summary> Test of GetRoles method, of class Owasp.Esapi.User.</summary>
        [Test]
        public void Test_GetRoles()
        {
            System.Console.Out.WriteLine("GetRoles");
            IAuthenticator authenticator = Esapi.Authenticator();
            string accountName = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            string password = Esapi.Authenticator().GenerateStrongPassword();
            string role = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_LOWERS);
            User user = (User) authenticator.CreateUser(accountName, password, password);
            user.AddRole(role);
            ArrayList roles = user.Roles;
            Assert.IsTrue(roles.Count > 0);
        }

        /// <summary> Test of GetScreenName method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_GetScreenName()
        {
            System.Console.Out.WriteLine("GetScreenName");
            User user = CreateTestUser("GetScreenName");
            string screenName = Esapi.Randomizer().GetRandomString(7, Encoder.CHAR_ALPHANUMERICS);
            user.ScreenName = screenName;
            Assert.AreEqual(screenName, user.ScreenName);
            Assert.IsFalse("ridiculous".Equals(user.ScreenName));
        }

        /// <summary> Test of IncrementFailedLoginCount method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_IncrementFailedLoginCount()
        {
            System.Console.Out.WriteLine("IncrementFailedLoginCount");
            User user = CreateTestUser("IncrementFailedLoginCount");
            user.Enable();
            Assert.AreEqual(0, user.FailedLoginCount);
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            try
            {
                user.LoginWithPassword("ridiculous");
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            Assert.AreEqual(1, user.FailedLoginCount);
            try
            {
                user.LoginWithPassword("ridiculous");
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            Assert.AreEqual(2, user.FailedLoginCount);
            try
            {
                user.LoginWithPassword("ridiculous");
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            Assert.AreEqual(3, user.FailedLoginCount);
            try
            {
                user.LoginWithPassword("ridiculous");
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            Assert.IsTrue(user.Locked);
        }

        /// <summary> Test of IsEnabled method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_IsEnabled()
        {
            System.Console.Out.WriteLine("IsEnabled");
            User user = CreateTestUser("IsEnabled");
            user.Disable();
            Assert.IsFalse(user.Enabled);
            user.Enable();
            Assert.IsTrue(user.Enabled);
        }


        /// <summary> Test of IsFirstRequest method, of class Owasp.Esapi.User.</summary>
        [Test]
        public void Test_IsFirstRequest()
        {
            System.Console.Out.WriteLine("IsFirstRequest");
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            IAuthenticator authenticator = Esapi.Authenticator();
            string password = authenticator.GenerateStrongPassword();
            IUser user = authenticator.GetUser("IsFirstRequest");
            if (user != null)
            {
                authenticator.RemoveUser("IsFirstRequest");
            }
            user = authenticator.CreateUser("IsFirstRequest", password, password);
            user.Enable();
            request.Params.Add(Esapi.SecurityConfiguration().PasswordParameterName, password);
            request.Params.Add(Esapi.SecurityConfiguration().UsernameParameterName, "IsFirstRequest");
            ((Authenticator) authenticator).Context = context;
            authenticator.Login();
            Assert.IsTrue(user.IsFirstRequest());
            authenticator.Login();
            Assert.IsFalse(user.IsFirstRequest());
            authenticator.Login();
            Assert.IsFalse(user.IsFirstRequest());
        }


        /// <summary> Test of IsInRole method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_IsInRole()
        {
            System.Console.Out.WriteLine("IsInRole");
            User user = CreateTestUser("IsInRole");
            string role = "TestRole";
            Assert.IsFalse(user.IsInRole(role));
            user.AddRole(role);
            Assert.IsTrue(user.IsInRole(role));
            Assert.IsFalse(user.IsInRole("Ridiculous"));
        }

        /// <summary> Test of xxx method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_IsLocked()
        {
            System.Console.Out.WriteLine("isLocked");
            User user = CreateTestUser("isLocked");
            user.Lock();
            Assert.IsTrue(user.Locked);
            user.Unlock();
            Assert.IsFalse(user.Locked);
        }

        /// <summary> Test of IsSessionAbsoluteTimeout method, of class
        /// Owasp.Esapi.IntrusionDetector.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_IsSessionAbsoluteTimeout()
        {
            // FIXME: ENHANCE shouldn't this just be one timeout method that does both checks???
            System.Console.Out.WriteLine("IsSessionAbsoluteTimeout");
		    String oldPassword = Esapi.Authenticator().GenerateStrongPassword();
		    User user = CreateTestUser(oldPassword);
		    long now = DateTime.Now.Ticks;
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            IHttpSession session = context.Session;
            ((Authenticator)Esapi.Authenticator()).Context = context;				
            
            // TODO - Not implemented
            //// set session creation -3 hours (default is 2 hour timeout)		
            //session.Timeout =  60 * 3;
            //Assert.IsTrue(user.IsSessionAbsoluteTimeout());
		
            //// set session creation -1 hour (default is 2 hour timeout)
            //session.Timeout = 60;
            //Assert.IsFalse(user.IsSessionAbsoluteTimeout());
	        }

        /// <summary> Test of IsSessionTimeout method, of class
        /// Owasp.Esapi.IntrusionDetector.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_IsSessionTimeout()
        {
            // TODO - Let's see how ASP.NET deals with this before testing.

            //System.Console.Out.WriteLine("IsSessionTimeout");
            //Authenticator instance = Authenticator();
            //string oldPassword = instance.GenerateStrongPassword();
            //User user = CreateTestUser(oldPassword);
            //long now = (System.DateTime.Now.Ticks - 621355968000000000) / 10000;
            //MockHttpContext context = new MockHttpContext();
            //IHttpSession session = context.Session;
            //int s1 = (int) now - 1000 * 60 * 60 * 3;
            //session.Timeout = s1;
            //Assert.IsTrue(user.IsSessionAbsoluteTimeout(session));
            //MockHttpContext context2 = new MockHttpContext();
            //IHttpSession session2 = context.Session;
            //int s2 = (int)now - 1000 * 60 * 60 * 3;
            //session2.Timeout = s2;
            //Assert.IsFalse(user.IsSessionTimeout(session2));


        }

        /// <summary> Test of LockAccount method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_Lock()
        {
            System.Console.Out.WriteLine("lock");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            user.Lock();
            Assert.IsTrue(user.Locked);
            user.Unlock();
            Assert.IsFalse(user.Locked);
        }

        /// <summary> Test of LoginWithPassword method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_LoginWithPassword()
        {
            System.Console.Out.WriteLine("LoginWithPassword");
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            IHttpSession session = context.Session;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            // Note: No really good way to do this check in the .NET sesison API.
            // Assert.IsFalse(session.Invalidated);
            User user = CreateTestUser("LoginWithPassword");
            user.Enable();
            user.LoginWithPassword("LoginWithPassword");
            Assert.IsTrue(user.LoggedIn);
            user.Logout();
            Assert.IsFalse(user.LoggedIn);
            Assert.IsFalse(user.Locked);
            try
            {
                user.LoginWithPassword("ridiculous");
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            Assert.IsFalse(user.LoggedIn);
            try
            {
                user.LoginWithPassword("ridiculous");
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            try
            {
                user.LoginWithPassword("ridiculous");
            }
            catch (AuthenticationException e)
            {
                // expected
            }
            Assert.IsTrue(user.Locked);
        }


        /// <summary> Test of Logout method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_Logout()
        {
            System.Console.Out.WriteLine("logout");
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            IHttpSession session = context.Session;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            // Note: No really good way to do this in .NET
            // Assert.IsFalse(session.Invalidated);
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            user.Enable();
            System.Console.Out.WriteLine(user.GetLastLoginTime().ToString("r"));
            user.LoginWithPassword(oldPassword);
            Assert.IsTrue(user.LoggedIn);
            // get new session after user logs in
            session = (IHttpSession) context.Session;            
            // Note: Need to fix this somehow
            // Assert.IsFalse(session.Invalidated);
            user.Logout();
            Assert.IsFalse(user.LoggedIn);
            ///Assert.IsTrue(session.Invalidated);
        }

        /// <summary> Test of RemoveRole method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_RemoveRole()
        {
            System.Console.Out.WriteLine("RemoveRole");
            string role = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_LOWERS);
            User user = CreateTestUser("RemoveRole");
            user.AddRole(role);
            Assert.IsTrue(user.IsInRole(role));
            user.RemoveRole(role);
            Assert.IsFalse(user.IsInRole(role));
        }

        /// <summary> Test of ResetCSRFToken method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_ResetCSRFToken()
        {
            System.Console.Out.WriteLine("ResetCSRFToken");
            User user = CreateTestUser("ResetCSRFToken");
            string token1 = user.ResetCsrfToken();
            string token2 = user.ResetCsrfToken();
            Assert.IsFalse(token1.Equals(token2));
        }

        /// <summary> Test reset password.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_ResetPassword()
        {
            System.Console.Out.WriteLine("ResetPassword");
            User user = CreateTestUser("ResetPassword");
            for (int i = 0; i < 20; i++)
            {
                Assert.IsTrue(user.VerifyPassword(user.ResetPassword()));
            }
        }

        /// <summary> Test of ResetRememberMeToken method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_ResetRememberToken()
        {
            System.Console.Out.WriteLine("ResetRememberToken");
            User user = CreateTestUser("ResetRememberToken");
            string token = user.ResetRememberToken();
            Assert.AreEqual(token, user.RememberToken);
        }

        /// <summary> Test of SetAccountName method, of class Owasp.Esapi.User.</summary>
        [Test]
        public void Test_SetAccountName()
        {
            System.Console.Out.WriteLine("SetAccountName");
            User user = CreateTestUser("SetAccountName");
            string accountName = Esapi.Randomizer().GetRandomString(7, Encoder.CHAR_ALPHANUMERICS);
            user.AccountName = accountName;
            Assert.AreEqual(accountName.ToLower(), user.AccountName);
            Assert.IsFalse("ridiculous".Equals(user.AccountName));
        }

        /// <summary> Test of SetExpirationTime method, of class Owasp.Esapi.User.</summary>
        [Test]
        public void Test_SetExpirationTime()
        {
            System.Console.Out.WriteLine("SetAccountName");
            string password = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            User user = CreateTestUser(password);
            user.ExpirationTime = new System.DateTime(0);
            Assert.IsTrue(user.Expired);
        }


        /// <summary> Test of SetRoles method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_SetRoles()
        {
            System.Console.Out.WriteLine("SetRoles");
            User user = CreateTestUser("SetRoles");
            user.AddRole("user");
            Assert.IsTrue(user.IsInRole("user"));
            ArrayList roles = new ArrayList();
            roles.Add("rolea");
            roles.Add("roleb");
            user.Roles = roles;
            Assert.IsFalse(user.IsInRole("user"));
            Assert.IsTrue(user.IsInRole("rolea"));
            Assert.IsTrue(user.IsInRole("roleb"));
            Assert.IsFalse(user.IsInRole("ridiculous"));
        }

        /// <summary> Test of SetScreenName method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_SetScreenName()
        {
            System.Console.Out.WriteLine("SetScreenName");
            User user = CreateTestUser("SetScreenName");
            string screenName = Esapi.Randomizer().GetRandomString(7, Encoder.CHAR_ALPHANUMERICS);
            user.ScreenName = screenName;
            Assert.AreEqual(screenName, user.ScreenName);
            Assert.IsFalse("ridiculous".Equals(user.ScreenName));
        }

        /// <summary> Test of UnlockAccount method, of class Owasp.Esapi.User.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        public void Test_Unlock()
        {
            System.Console.Out.WriteLine("UnlockAccount");
            IAuthenticator authenticator = Esapi.Authenticator();
            string oldPassword = authenticator.GenerateStrongPassword();
            User user = CreateTestUser(oldPassword);
            user.Lock();
            Assert.IsTrue(user.Locked);
            user.Unlock();
            Assert.IsFalse(user.Locked);
        }
    }
}
