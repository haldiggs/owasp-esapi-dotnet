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
        [Test]
        public void Test_IsValidCreditCard()
        {
            System.Console.Out.WriteLine("IsValidCreditCard");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidCreditCard("test", "1234 9876 0000 0008", false));
            Assert.IsTrue(validator.IsValidCreditCard("test", "1234987600000008", false));
            Assert.IsFalse(validator.IsValidCreditCard("test", "12349876000000081", false));
            Assert.IsFalse(validator.IsValidCreditCard("test", "4417 1234 5678 9112", false));
        }

        /// <summary> Test of IsValidInput method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidInput()
        {
            System.Console.Out.WriteLine("IsValidInput");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidInput("test", "Email", "jeff.williams@aspectsecurity.com", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "Email", "jeff.williams@@aspectsecurity.com", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "Email", "jeff.williams@aspectsecurity", 100, false));
            Assert.IsTrue(validator.IsValidInput("test", "IPAddress", "123.168.100.234", 100, false));
            Assert.IsTrue(validator.IsValidInput("test", "IPAddress", "192.168.1.234", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "IPAddress", "..168.1.234", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "IPAddress", "10.x.1.234", 100, false));
            Assert.IsTrue(validator.IsValidInput("test", "URL", "http://www.aspectsecurity.com", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "URL", "http:///www.aspectsecurity.com", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "URL", "http://www.aspect security.com", 100, false));
            Assert.IsTrue(validator.IsValidInput("test", "SSN", "078-05-1120", 100, false));
            Assert.IsTrue(validator.IsValidInput("test", "SSN", "078 05 1120", 100, false));
            Assert.IsTrue(validator.IsValidInput("test", "SSN", "078051120", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "SSN", "987-65-4320", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "SSN", "000-00-0000", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "SSN", "(555) 555-5555", 100, false));
            Assert.IsFalse(validator.IsValidInput("test", "SSN", "test", 100, false));
        }

        /// <summary> Test of IsValidSafeHTML method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidSafeHTML()
        {
            System.Console.Out.WriteLine("IsValidSafeHTML");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidSafeHtml("test", "<b>Jeff</b>", 100, false));
            Assert.IsTrue(validator.IsValidSafeHtml("test", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false));
            Assert.IsFalse(validator.IsValidSafeHtml("test", "Test. <script>alert(document.cookie)</script>", 100, false));
            //This one can't be caught properly by Anti-Samy
            Assert.IsFalse(validator.IsValidSafeHtml("test", "\" onload=\"alert(document.cookie)\" ", 100, false));
        }

       
        //Test of getValidSafeHTML method, of class org.owasp.esapi.Validator.
        [Test]
        public void Test_GetValidSafeHTML()
        {
            // TODO - Method not implemented yet
            //Console.Out.WriteLine("Test_GetValidSafeHTML");
            //IValidator validator = Esapi.Validator();
            //String test1 = "<b>Jeff</b>";
            //String result1 = validator.GetValidSafeHtml("test", test1, 100, false);
            //Assert.AreEqual(test1, result1);

            //String test2 = "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>";
            //String result2 = validator.GetValidSafeHtml("test", test2, 100, false);
            //Assert.AreEqual(test2, result2);

            //String test3 = "Test. <script>alert(document.cookie)</script>";
            //String result3 = validator.GetValidSafeHtml("test", test3, 100, false);
            //Assert.AreEqual("Test.", result3);

            // FIXME: ENHANCE waiting for a way to validate text headed for an attribute for scripts		
            // This would be nice to catch, but just looks like text to AntiSamy
            //		String test4 = "\" onload=\"alert(document.cookie)\" ";
            //		String result4 = validator.GetValidSafeHtml("test", test4);
            //		Assert.AreEqual("", result4);
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
            Assert.IsTrue(validator.IsValidListItem("test", "one", list));
            Assert.IsFalse(validator.IsValidListItem("test", "three", list));
        }

        /// <summary> Test of IsValidNumber method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidNumber()
        {
            System.Console.Out.WriteLine("IsValidNumber");
            IValidator validator = Esapi.Validator();
            //testing negative range
            Assert.IsFalse(validator.IsValidNumber("test", "-4", 1, 10, false));
            Assert.IsTrue(validator.IsValidNumber("test", "-4", -10, 10, false));
            //testing null value
            Assert.IsTrue(validator.IsValidNumber("test", null, -10, 10, true));
            Assert.IsFalse(validator.IsValidNumber("test", null, -10, 10, false));
            //testing empty string
            Assert.IsTrue(validator.IsValidNumber("test", "", -10, 10, true));
            Assert.IsFalse(validator.IsValidNumber("test", "", -10, 10, false));
            //testing improper range
            Assert.IsFalse(validator.IsValidNumber("test", "5", 10, -10, false));
            //testing non-integers
            Assert.IsTrue(validator.IsValidNumber("test", "4.3214", -10, 10, true));
            Assert.IsTrue(validator.IsValidNumber("test", "-1.65", -10, 10, true));
            //other testing
            Assert.IsTrue(validator.IsValidNumber("test", "4", 1, 10, false));
            Assert.IsTrue(validator.IsValidNumber("test", "400", 1, 10000, false));
            Assert.IsTrue(validator.IsValidNumber("test", "400000000", 1, 400000000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "4000000000000", 1, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "alsdkf", 10, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "--10", 10, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "14.1414234x", 10, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "Infinity", 10, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "-Infinity", 10, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "NaN", 10, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "-NaN", 10, 10000, false));
            Assert.IsFalse(validator.IsValidNumber("test", "+NaN", 10, 10000, false));
            Assert.IsTrue(validator.IsValidNumber("test", "1e-6", -999999999, 999999999, false));
            Assert.IsTrue(validator.IsValidNumber("test", "-1e-6", -999999999, 999999999, false));
        }

        // <summary> Test of IsValidInteger method, of class Owasp.Esapi.Validator.</summary>
        public void testIsValidInteger()
        {
            Console.Out.WriteLine("IsValidInteger");
            IValidator validator = Esapi.Validator();
            //testing negative range
            Assert.IsFalse(validator.IsValidInteger("test", "-4", 1, 10, false));
            Assert.IsTrue(validator.IsValidInteger("test", "-4", -10, 10, false));
            //testing null value
            Assert.IsTrue(validator.IsValidInteger("test", null, -10, 10, true));
            Assert.IsFalse(validator.IsValidInteger("test", null, -10, 10, false));
            //testing empty string
            Assert.IsTrue(validator.IsValidInteger("test", "", -10, 10, true));
            Assert.IsFalse(validator.IsValidInteger("test", "", -10, 10, false));
            //testing improper range
            Assert.IsFalse(validator.IsValidInteger("test", "5", 10, -10, false));
            //testing non-integers
            Assert.IsFalse(validator.IsValidInteger("test", "4.3214", -10, 10, true));
            Assert.IsFalse(validator.IsValidInteger("test", "-1.65", -10, 10, true));
            //other testing
            Assert.IsTrue(validator.IsValidInteger("test", "4", 1, 10, false));
            Assert.IsTrue(validator.IsValidInteger("test", "400", 1, 10000, false));
            Assert.IsTrue(validator.IsValidInteger("test", "400000000", 1, 400000000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "4000000000000", 1, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "alsdkf", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "--10", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "14.1414234x", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "Infinity", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "-Infinity", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "NaN", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "-NaN", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "+NaN", 10, 10000, false));
            Assert.IsFalse(validator.IsValidInteger("test", "1e-6", -999999999, 999999999, false));
            Assert.IsFalse(validator.IsValidInteger("test", "-1e-6", -999999999, 999999999, false));
        }

        /// <summary> Test of GetValidDate method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_GetValidDate()
        {
            System.Console.Out.WriteLine("GetValidDate");            
            IValidator validator = Esapi.Validator();
            Assert.IsTrue((validator.GetValidDate("test", "June 23, 1967", DateTimeFormatInfo.CurrentInfo, false) != null));            
            try
            {
                validator.GetValidDate("test", "freakshow", DateTimeFormatInfo.CurrentInfo, false);
            }
            catch (Exception e)
            {
                //Expected
            }
            try
            {
                validator.GetValidDate("test", "June 32, 2008", DateTimeFormatInfo.CurrentInfo, false);
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
            Assert.IsTrue(validator.IsValidFileName("test", "aspect.jar", false));
            Assert.IsFalse(validator.IsValidFileName("test", "", false));
            try
            {
                validator.IsValidFileName("test", "abc/def", false);
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
            Assert.IsTrue(validator.IsValidDirectoryPath("test", "c:/", false));
            Assert.IsTrue(validator.IsValidDirectoryPath("test", "c:\\windows", false));
            Assert.IsTrue(validator.IsValidDirectoryPath("test", "d:/tempdir/", false));
            // FIXME: ENHANCE doesn't accept filenames, just directories - should it?
            // Assert.IsTrue( validator.IsValidDirectoryPath(
            // "c:\\Windows\\System32\\cmd.exe" ) );
            Assert.IsFalse(validator.IsValidDirectoryPath("test", "c:\\temp\\..\\etc", false));
        }

        /// <summary> Test of IsValidPrintable method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidPrintable()
        {
            System.Console.Out.WriteLine("IsValidPrintable");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidPrintable("name", "abcDEF", 100, false));
            Assert.IsTrue(validator.IsValidPrintable("name", "!@#R()*$;><()", 100, false));
            
            byte[] bytes = new byte[] { (byte)(0x60), (byte)(0xFF), (byte)(0x10), (byte)(0x25) };
            Assert.IsFalse(validator.IsValidPrintable("name", bytes, 100, false));
            Assert.IsFalse(validator.IsValidPrintable("name", "%08", 100, false));
        }

        /// <summary> Test of IValidFileContent method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidFileContent()
        {
            System.Console.Out.WriteLine("IsValidFileContent");
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            byte[] content = encoding.GetBytes("This is some file content");
            IValidator validator = Esapi.Validator();
            Assert.IsTrue(validator.IsValidFileContents("test", content, 100, false));
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
            Assert.IsTrue(validator.IsValidFileUpload("test", filepath, filename, content, 100, false));
        }

        /// <summary> Test of IsValidHttpRequestParameterSet method, of class Owasp.Esapi.Validator.</summary>
        [Test]
        public void Test_IsValidHttpRequestParameterSet()
        {            
            System.Console.Out.WriteLine("IsValidHttpRequestParameterSet");
            
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
            
            Assert.IsTrue(validator.IsValidHttpRequestParameterSet("HttpParameters", requiredNames, optionalNames));
            request.Params.Add("p4", "value");
            request.Params.Add("p5", "value");
            request.Params.Add("p6", "value");
            Assert.IsTrue(validator.IsValidHttpRequestParameterSet("HttpParameters", requiredNames, optionalNames));
            request.Params.Remove("p1");
            Assert.IsFalse(validator.IsValidHttpRequestParameterSet("HttpParameters", requiredNames, optionalNames));
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
