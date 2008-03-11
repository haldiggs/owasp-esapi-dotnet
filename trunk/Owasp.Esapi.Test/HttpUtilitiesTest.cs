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
using HttpInterfaces;
using Owasp.Esapi.Test.Http;
using System.IO;
using System.Collections;
using System.Web;
using Owasp.Esapi.Interfaces;
using System.Text;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class HTTPUtilitiesTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class HttpUtilitiesTest
    {
        /// <summary> Instantiates a new HTTP utilities test.
        /// 
        /// </summary>
        public HttpUtilitiesTest():this(null)
        {
        }
        
        
        /// <summary> Instantiates a new HTTP utilities test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public HttpUtilitiesTest(string testName)
		{
		}
        
        /// <summary> Test of addCSRFToken method, of class Owasp.Esapi.HTTPUtilities.</summary>
        [Test]
        public void Test_AddCSRFToken()
        {            
            System.Console.Out.WriteLine("AddCSRFToken");
            IAuthenticator authenticator = Esapi.Authenticator();
            ((Authenticator)authenticator).Context = new MockHttpContext();
            string username = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            IUser user = authenticator.CreateUser(username, "AddCSRFToken", "AddCSRFToken");
            authenticator.SetCurrentUser(user);
            Assert.IsTrue(Esapi.HttpUtilities().AddCsrfToken("/test1").Contains("?"));
            Assert.IsTrue(Esapi.HttpUtilities().AddCsrfToken("/test1?one=two").Contains("&"));
        }

        /// <summary> Test of ChangeSessionIdentifier method, of class Owasp.Esapi.HTTPUtilities.
        /// 
        /// </summary>
        /// <throws>  ValidationException the validation exception </throws>
        /// <throws>  IOException Signals that an I/O exception has occurred. </throws>
        /// <throws>  AuthenticationException the authentication exception </throws>
        [Test]
        public void Test_ChangeSessionIdentifier()
        {
            System.Console.Out.WriteLine("ChangeSessionIdentifier");
            IHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpSession session = context.Session;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            session["one"] = "one";
            session["two"] = "two";
            session["three"] = "three";            
            string id1 = session.SessionID;
            session = (MockHttpSession)Esapi.HttpUtilities().ChangeSessionIdentifier();
            string id2 = session.SessionID;
            Assert.IsTrue(!id1.Equals(id2));
            Assert.AreEqual("one", (string)session["one"]);
        }

        /// <summary> Test of GetFileUploads method, of class Owasp.Esapi.HTTPUtilities.</summary>
        /// <throws>  IOException  </throws>
        [Test]
        public void Test_GetFileUploads()
        {
            System.Console.Out.WriteLine("GetFileUploads");            
            FileInfo home = ((SecurityConfiguration)Esapi.SecurityConfiguration()).ResourceDirectory;
            byte[] bytes = GetBytesFromFile(new FileInfo(home.FullName + "\\" + "multipart.txt"));
            
            System.Console.Out.WriteLine("===========\n" + new ASCIIEncoding().GetString(bytes) + "\n===========");
            MockHttpContext context = new MockHttpContext();            
            context.Request = new MockHttpRequest("/test", bytes);
            ((Authenticator)Esapi.Authenticator()).Context = context;
            MockHttpPostedFile file = new MockHttpPostedFile("c:/mydir/destination.txt");
            IHttpFileCollection fileCollection = new MockHttpFileCollection();
            ((MockHttpFileCollection)fileCollection).AddFile(file);
            ((MockHttpRequest) context.Request).Files = fileCollection;
            try
            {
                Esapi.HttpUtilities().GetSafeFileUploads(home, home);
            }
            catch (ValidationException e)
            {
                Assert.Fail();
            }
        }

        private byte[] GetBytesFromFile(FileInfo file)
        {
            Stream fileStream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read);
            long length = file.Length;
            byte[] bytes = new byte[length];


            long offset = 0;
            long remaining = length;
            while (remaining > 0)
            {
                // Note: Check up on rules of casting here for int overflow
                int read = fileStream.Read(bytes, (int) offset, (int) remaining);
                if (read <= 0)
                {
                    throw new EndOfStreamException(String.Format("End of stream reached with {0} bytes left to read", remaining));
                }
                remaining -= read;
                offset += read;
            }
            
            fileStream.Close();
            return bytes;
        }

        /// <summary> Test of IsValidHTTPRequest method, of class Owasp.Esapi.HTTPUtilities.</summary>
        [Test]
        public void Test_IsValidHTTPRequest()
        {
            System.Console.Out.WriteLine("IsValidHTTPRequest");
            MockHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            request.Params.Add("p1", "v1");
            request.Params.Add("p2", "v3");
            request.Params.Add("p3", "v2");
            request.Params.Add("h1", "v1");
            request.Headers.Add("h2", "v1");
            request.Headers.Add("h3", "v1");            
            request.Cookies.Add(new HttpCookie("c1", "v1"));
            request.Cookies.Add(new HttpCookie("c2", "v2"));
            request.Cookies.Add(new HttpCookie("c3", "v3"));
            Assert.IsTrue(Esapi.Validator().IsValidHttpRequest(request));
            request.Params.Add("bad_name", "bad*value");
            request.Headers.Add("bad_name", "bad*vaslue");
            request.Cookies.Add(new HttpCookie("bad_name", "bad*value"));
            Assert.IsFalse(Esapi.Validator().IsValidHttpRequest(request));
        }


        /// <summary> Test of KillAllCookies method, of class Owasp.Esapi.HTTPUtilities.</summary>
        [Test]
        public void Test_KillAllCookies()
        {
            System.Console.Out.WriteLine("KillAllCookies");
            IHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            Assert.IsTrue((response.Cookies.Count == 0));
            
            request.Cookies.Add(new System.Web.HttpCookie("test1", "1"));
            request.Cookies.Add(new System.Web.HttpCookie("test2", "2"));
            request.Cookies.Add(new System.Web.HttpCookie("test3", "3"));
            Esapi.HttpUtilities().KillAllCookies();
            // this tests getHeaders because we're using addHeader in our setCookie method
            Assert.IsTrue(response.Headers["Set-Cookie"].Split(',').Length == 3);
        }

        /// <summary> Test of KillCookie method, of class Owasp.Esapi.HTTPUtilities.</summary>
        [Test]
        public void Test_KillCookie()
        {
            System.Console.Out.WriteLine("KillCookie");
            IHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            IHttpResponse response = context.Response;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            Assert.IsTrue(response.Cookies.Count == 0);
            request.Cookies.Add(new System.Web.HttpCookie("test1", "1"));
            request.Cookies.Add(new System.Web.HttpCookie("test2", "2"));
            request.Cookies.Add(new System.Web.HttpCookie("test3", "3"));
            Esapi.HttpUtilities().KillCookie("test1");
            // this tests Headers because we're using Header.add in our SetCookie method
            // Note: this is not how we are going to do it. BTW, 1 seems wrong, right?
            Assert.IsTrue(response.Headers["Set-Cookie"].Split(',').Length == 1);
        }

        /// <summary> Test of SendSafeRedirect method, of class Owasp.Esapi.HTTPUtilities.
        /// 
        /// </summary>
        /// <throws>  ValidationException the validation exception </throws>
        /// <throws>  IOException Signals that an I/O exception has occurred. </throws>
        [Test]
        public void Test_SendSafeRedirect()
        {
            System.Console.Out.WriteLine("SendSafeRedirect");
            MockHttpContext context = new MockHttpContext();
            ((Authenticator)Esapi.Authenticator()).Context = context;
            IHttpResponse response = context.Response;
            try
            {
                Esapi.HttpUtilities().SafeSendRedirect("test", "/test1/abcdefg");
                Esapi.HttpUtilities().SafeSendRedirect("test", "/test2/1234567");
            }
            catch (ValidationException e)
            {
                Assert.Fail();
            }
            try
            {
                Esapi.HttpUtilities().SafeSendRedirect("test", "/ridiculous");
                Assert.Fail();
            }
            catch (ValidationException e)
            {
                // expected
            }
        }

        /// <summary> Test of SetCookie method, of class Owasp.Esapi.HTTPUtilities.</summary>
        [Test]
        public void Test_SetCookie()
        {
            System.Console.Out.WriteLine("SetCookie");
            IHttpContext context = new MockHttpContext();
            IHttpResponse response = context.Response;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            Assert.IsTrue((response.Cookies.Count == 0));
            Esapi.HttpUtilities().SafeAddCookie("test1", "test1", 10000, "test", "/");
            Esapi.HttpUtilities().SafeAddCookie("test2", "test2", 10000, "test", "/");
            Assert.IsTrue(response.Headers["Set-Cookie"].Split(',').Length == 2);
        }

        /// <summary> Test of SetNoCacheHeaders.</summary>
        [Test]
        public void Test_SetNoCacheHeaders()
        {
            System.Console.Out.WriteLine("SetNoCacheHeaders");
            IHttpContext context = new MockHttpContext();
            IHttpResponse response = context.Response;
            ((Authenticator)Esapi.Authenticator()).Context = context;
            Assert.IsTrue((response.Headers.Count == 0));
            response.Headers.Add("test1", "1");
            response.Headers.Add("test2", "2");
            response.Headers.Add("test3", "3");
            Assert.IsFalse((response.Headers.Count == 0));
            IHttpUtilities httpUtilities = Esapi.HttpUtilities();
            httpUtilities.SetNoCacheHeaders();
            Assert.IsTrue(response.Headers["Cache-Control"] != null);
            Assert.IsTrue(response.Headers["Expires"] != null);
        }
    }
}
