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
using System.Collections;
using System.IO;
using Owasp.Esapi.Interfaces;
using System.Globalization;
using HttpInterfaces;
using Owasp.Esapi.Test.Http;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class ValidatorTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    
    [TestFixture]
    public class ValidatorTest
    {

        /// <summary> Instantiates a new validator test.
        /// 
        /// </summary>
        public ValidatorTest():this(null)
        {
        }

        /// <summary> Instantiates a new validator test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public ValidatorTest(string testName)
        {
        }
        /// <summary> Test of IsValidCreditCard method, of class Owasp.Esapi.Validator.</summary>
        public void Test_IsValidCreditCard()
        {
            System.Console.Out.WriteLine("IsValidCreditCard");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidCreditCard("test", "1234 9876 0000 0008"));
            Assert.IsTrue(validator.IsValidCreditCard("test", "1234987600000008"));
            Assert.IsFalse(validator.IsValidCreditCard("test", "12349876000000081"));
            Assert.IsFalse(validator.IsValidCreditCard("test", "4417 1234 5678 9112"));
        }

        /// <summary> Test of IsValidDataFromBrowser method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidDataFromBrowser()
        {
            System.Console.Out.WriteLine("IsValidDataFromBrowser");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidDataFromBrowser("test", "Email", "jeff.williams@aspectsecurity.com"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "Email", "jeff.williams@@aspectsecurity.com"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "Email", "jeff.williams@aspectsecurity"));
            Assert.IsTrue(validator.IsValidDataFromBrowser("test", "IPAddress", "123.168.100.234"));
            Assert.IsTrue(validator.IsValidDataFromBrowser("test", "IPAddress", "192.168.1.234"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "IPAddress", "..168.1.234"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "IPAddress", "10.x.1.234"));
            Assert.IsTrue(validator.IsValidDataFromBrowser("test", "URL", "http://www.aspectsecurity.com"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "URL", "http:///www.aspectsecurity.com"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "URL", "http://www.aspect security.com"));
            Assert.IsTrue(validator.IsValidDataFromBrowser("test", "SSN", "078-05-1120"));
            Assert.IsTrue(validator.IsValidDataFromBrowser("test", "SSN", "078 05 1120"));
            Assert.IsTrue(validator.IsValidDataFromBrowser("test", "SSN", "078051120"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "SSN", "987-65-4320"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "SSN", "000-00-0000"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "SSN", "(555) 555-5555"));
            Assert.IsFalse(validator.IsValidDataFromBrowser("test", "SSN", "test"));
        }

        /// <summary> Test of IsValidSafeHTML method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidSafeHTML()
        {
            System.Console.Out.WriteLine("IsValidSafeHTML");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidSafeHtml("test", "<b>Jeff</b>"));
            Assert.IsTrue(validator.IsValidSafeHtml("test", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>"));
            Assert.IsFalse(validator.IsValidSafeHtml("test", "Test. <script>alert(document.cookie)</script>"));
            Assert.IsFalse(validator.IsValidSafeHtml("test", "\" onload=\"alert(document.cookie)\" "));
        }

        /// <summary> Test of IsValidListItem method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidListItem()
        {
            System.Console.Out.WriteLine("IsValidListItem");
            IValidator validator = Esapi.Validator();
            System.Collections.IList list = new ArrayList();
            list.Add("one");
            list.Add("two");
            Assert.IsTrue(validator.IsValidListItem(list, "one"));
            Assert.IsFalse(validator.IsValidListItem(list, "three"));
        }

        /// <summary> Test of IsValidNumber method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidNumber()
        {
            System.Console.Out.WriteLine("IsValidNumber");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidNumber("4"));
            Assert.IsTrue(validator.IsValidNumber("400"));
            Assert.IsTrue(validator.IsValidNumber("4000000000000"));
            Assert.IsFalse(validator.IsValidNumber("alsdkf"));
            Assert.IsFalse(validator.IsValidNumber("--10"));
            Assert.IsFalse(validator.IsValidNumber("14.1414234x"));
        }

        /// <summary> Test of GetValidDate method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_GetValidDate()
        {
            System.Console.Out.WriteLine("GetValidDate");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue((validator.GetValidDate("test", "June 23, 1967", DateTimeFormatInfo.CurrentInfo) != null));
            try
            {
                validator.GetValidDate("test", "freakshow", DateTimeFormatInfo.CurrentInfo);
            }
            catch (Exception e)
            {
                //Expected
            }
            try
            {
                validator.GetValidDate("test", "June 32, 2008", DateTimeFormatInfo.CurrentInfo);
            }
            catch (Exception e)
            {
                //Expected
            }

        }

        /// <summary> Test of IsValidFileName method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidFileName()
        {
            System.Console.Out.WriteLine("test", "IsValidFileName");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidFileName("test", "aspect.jar"));
            Assert.IsFalse(validator.IsValidFileName("test", ""));
            try
            {
                validator.IsValidFileName("test", "abc/def");
            }
            catch (IntrusionException e)
            {
                // expected
            }
        }

        /// <summary> Test of IsValidFilePath method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidFilePath()
        {
            System.Console.Out.WriteLine("IsValidFilePath");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidDirectoryPath("test", "/"));
            Assert.IsTrue(validator.IsValidDirectoryPath("test", "c:\\temp"));
            Assert.IsTrue(validator.IsValidDirectoryPath("test", "/etc/config"));
            // FIXME: ENHANCE doesn't accept filenames, just directories - should it?
            // Assert.IsTrue( instance.IsValidDirectoryPath(
            // "c:\\Windows\\System32\\cmd.exe" ) );
            Assert.IsFalse(validator.IsValidDirectoryPath("test", "c:\\temp\\..\\etc"));
        }

        /// <summary> Test of IsValidPrintable method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidPrintable()
        {
            System.Console.Out.WriteLine("IsValidPrintable");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidPrintable("abcDEF"));
            Assert.IsTrue(validator.IsValidPrintable("!@#R()*$;><()"));
            
            byte[] bytes = new byte[] { (byte)(0x60), (byte)(0xFF), (byte)(0x10), (byte)(0x25) };
            Assert.IsFalse(validator.IsValidPrintable(bytes));
            Assert.IsFalse(validator.IsValidPrintable("%08"));
        }

        /// <summary> Test of IValidFileContent method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidFileContent()
        {
            System.Console.Out.WriteLine("IsValidFileContent");
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            byte[] content = encoding.GetBytes("This is some file content");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidFileContent("test", content));
        }

        /// <summary> Test of IsValidFileUpload method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidFileUpload()
        {
            System.Console.Out.WriteLine("IsValidFileUpload");

            string filepath = "/etc";
            string filename = "aspect.jar";
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            byte[] content = encoding.GetBytes("This is some file content");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidFileUpload("test", filepath, filename, content));
        }

        /// <summary> Test of IsValidParameterSet method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidParameterSet()
        {            
            System.Console.Out.WriteLine("IsValidParameterSet");
            
            ArrayList requiredNames = new ArrayList();
            requiredNames.Add("p1");
            requiredNames.Add("p2");
            requiredNames.Add("p3");
            
            ArrayList optionalNames = new ArrayList();
            optionalNames.Add("p4");
            optionalNames.Add("p5");
            optionalNames.Add("p6");


            IHttpContext context = new MockHttpContext();
            IHttpRequest request = context.Request;
            ((Authenticator)Esapi.Authenticator()).Context = context;

            ArrayList actualNames = new ArrayList();
            request.Params.Add("p1", "value");
            request.Params.Add("p2", "value");
            request.Params.Add("p3", "value");


            IValidator validator = Esapi.Validator();
            
            Assert.IsTrue(validator.IsValidParameterSet(requiredNames, optionalNames));
            request.Params.Add("p4", "value");
            request.Params.Add("p5", "value");
            request.Params.Add("p6", "value");
            Assert.IsTrue(validator.IsValidParameterSet(requiredNames, optionalNames));
            request.Params.Remove("p1");
            Assert.IsFalse(validator.IsValidParameterSet(requiredNames, optionalNames));
        }

        /// <summary> Test safe read line.</summary>
        [Test]
        public void Test_SafeReadLine()
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            MemoryStream s = new MemoryStream(encoding.GetBytes("testString"));
            IValidator validator = Esapi.Validator();
            try
            {
                validator.SafeReadLine(s, -1);
                Assert.Fail();
            }
            catch (ValidationException e)
            {
                // Expected
            }

            // Doing this instead of ByteInputArrayStream.rest().
            s.Position = 0;            
            try
            {
                validator.SafeReadLine(s, 4);
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // Expected
            }

            s.Position = 0;                         
            try
            {
                string u = validator.SafeReadLine(s, 20);
                Assert.IsTrue(u.Equals("testString"));
            }
            catch (ValidationException e)
            {
                Assert.Fail();
            }
        }
    }
}
