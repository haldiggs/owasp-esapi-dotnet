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
using System.IO;
using System.Web;
using NUnit.Framework;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class SafeFileTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class SafeFileTest
    {
        /// <summary> Instantiates a new SafeFile test.
        /// 
        /// </summary>    
        public SafeFileTest()
            : this(null)
        {

        }

        /// <summary> Instantiates a new SafeFile test.
        /// 
        /// </summary>
        /// <param name="testName">The test name
        /// </param>
        public SafeFileTest(String testName)
        {

        }

        String pathWithNullByte = "/temp/file.txt" + (char)0;

        [Test]
        public void Test_DotNetFileInjection()
        {
            Console.Out.WriteLine("Test_DotNetFileInjection");
            for (int i = 1; i < 512; i++)
            {
                String goodFileName = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties" + (char)i;
                FileInfo goodFile;
                try
                {
                    goodFile = new FileInfo(goodFileName);
                    if (goodFile.Exists)
                    {
                        Console.Out.WriteLine("  Fail filename.txt" + (char)i + " (" + i + ")");                        
                    }
                    FileInfo goodFile2 = new FileInfo(goodFileName + "test");
                    if (goodFile2.Exists)
                    {
                        Console.Out.WriteLine("  Fail c:\\filename.txt" + (char)i + "test.xml (" + i + ")");                        
                    }
                } catch (ArgumentException ex)
                {
                    //Expected                    
                }
                catch (NotSupportedException ex)
                {

                }

            }
        }

        [Test]
        public void Test_MultipleDotNetFileInjection()
        {
            Console.Out.WriteLine("Test_MultipleDotNetFileInjection");
            for (int i = 1; i < 512; i++)
            {
                String goodFileName = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties" + (char)i + (char)i + (char)i;
                FileInfo goodFile;
                try
                {
                    goodFile = new FileInfo(goodFileName);
                    if (goodFile.Exists)
                    {
                        Console.Out.WriteLine("  Fail filename.txt" + (char)i + (char)i + (char)i + " (" + i + ") 3x");
                    }
                    FileInfo goodFile2 = new FileInfo(goodFileName + "test");
                    if (goodFile2.Exists)
                    {
                        Console.Out.WriteLine("  Fail c:\\filename.txt" + (char)i + (char)i + (char)i + "test.xml (" + i + ") 3x");
                    }
                }
                catch (ArgumentException ex)
                {
                    //Expected                    
                }
                catch (NotSupportedException ex)
                {

                }
            }
        }

        [Test]
        public void Test_AlternateDataStream()
        {
            Console.Out.WriteLine("Test_AlternateDataStream");
            try
            {
                String goodFileName = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties:secret.txt";
                FileInfo goodFile = new FileInfo(goodFileName);
                Assert.Fail();
            }
            catch
            {
                //Expected
            }
                        
        }
	

        
        
        [Test]
        public void Test_DotNetDirInjection()
        {
            Console.Out.WriteLine("Test_DotNetDirInjection");
            for (int i = 0; i < 512; i++)
            {
                String goodFileName = Esapi.SecurityConfiguration().ResourceDirectory.ToString() + (char)i;
                try
                {
                    FileInfo goodFile = new FileInfo(goodFileName);

                    if (goodFile.Exists)
                    {
                        Console.Out.WriteLine("  Fail c:\\dirpath" + (char)i + " (" + i + ")");
                    }
                    FileInfo goodFile2 = new FileInfo(goodFileName + "test");
                    if (goodFile2.Exists)
                    {
                        Console.Out.WriteLine("  Fail c:\\dirpath" + (char)i + "test.xml (" + i + ")");
                    }
                } catch (ArgumentException ex)
                {
                    // Expected
                }
                catch (NotSupportedException ex)
                {

                }
            }
        }

        [Test]
        public void Test_NormalPercentEncodedFileInjection()
        {
            Console.Out.WriteLine("Test_NormalPercentEncodedFileInjection");
            for (int i = 0; i < 256; i++)
            {
                String enc1 = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties" + "%" + ToHex((byte)i);
                String dec1 = HttpUtility.UrlDecode(enc1);
                try
                {
                    FileInfo goodFile = new FileInfo(dec1);
                    if (goodFile.Exists)
                    {
                        Console.Out.WriteLine("  Fail: " + enc1);
                    }
                }
                catch (ArgumentException ex)
                {
                    // Expected                    
                }
                catch (NotSupportedException ex)
                {
                    
                }
            }
        }
            
        [Test]
        public void Test_WeirdPercentEncodedFileInjection()
        {
            Console.Out.WriteLine("Test_WeirdPercentEncodedFileInjection");
            for (int i = 0; i < 256; i++)
            {
                String enc2 = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties" + "%u00" + ToHex((byte)i);
                String dec2 = HttpUtility.UrlDecode(enc2);
                try
                {
                    FileInfo goodFile2 = new FileInfo(dec2);

                    if (goodFile2.Exists)
                    {
                        Console.Out.WriteLine("  Fail: " + enc2);
                    }
                }
                catch (ArgumentException ex)
                {
                    // Expected                    
                }
                catch (NotSupportedException ex)
                {

                }
            }
        }


        [Test]
        public void Test_CreateSafeFile()
        {
            Console.Out.WriteLine("SafeFile");
            // verify file exists and test safe constructors
            String goodFileName = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties";
            try
            {
                FileInfo goodFile = new FileInfo(goodFileName);
                Assert.IsTrue(goodFile.Exists);

                // test string constructor
                SafeFile goodFile2 = new SafeFile(goodFileName);
                Assert.IsTrue(goodFile2.SafeFileInfo.Exists);

                // test URI constructor
                String uri = "file:///" + Esapi.SecurityConfiguration().ResourceDirectory.ToString().Replace("\\", "/") + "/ESAPI.properties";
                Console.Out.WriteLine(uri);
                SafeFile goodFile3 = new SafeFile(new Uri(uri));
                Assert.IsTrue(goodFile3.SafeFileInfo.Exists);
            }
            catch (Exception e)
            {
                Assert.Fail();
            }

            // test percent encoded null byte
            try
            {
                String pathWithPercentEncodedNullByte = "/temp/file%00.txt";
                new SafeFile(pathWithPercentEncodedNullByte);
                Assert.Fail("Exception not thrown when Safe File created with encoded null byte.");
            }
            catch (Exception e)
            {
                // expected
            }

            // test illegal characters
            try
            {
                String pathWithPercentEncodedNullByte = "/temp/file?.txt";
                new SafeFile(pathWithPercentEncodedNullByte);
                Assert.Fail("Exception not thrown when Safe File created with encoded null byte.");
            }
            catch (Exception e)
            {
                // expected
            }

            // test safe file exists
            String goodFileName2 = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties";
            try
            {
                FileInfo goodFile2 = new SafeFile(goodFileName2).SafeFileInfo;
                Assert.IsTrue(goodFile2.Exists);
            }
            catch (ValidationException e)
            {
                Assert.Fail(String.Format("Exception thrown when attempting to access properties file at {0}", new object[] { goodFileName2 }));
            }

            // test null byte
            try
            {
                new SafeFile(pathWithNullByte);
                Assert.Fail("No exception thrown when creating Safe File with null byte in path");
            }
            catch (ValidationException e)
            {
                // expected
            }

            // test high byte
            try
            {
                String pathWithHighByte = "/temp/file.txt" + (char)160;
                new SafeFile(pathWithHighByte);
                Assert.Fail("No exception thrown when creating Safe File with high byte in path");
            }
            catch (ValidationException e)
            {
                // expected
            }
        }

        // test parent constructor
        [Test]
        public void Test_CreateSafeFileParentConstructor()
        {
            Console.Out.WriteLine("SafeFile parent constructor");
            // TODO: Figure out if we need this test.
            
            
            //FileInfo parent = new FileInfo("/");
            //try
            //{
            //    new SafeFile(parent, pathWithNullByte);
            //    Assert.Fail("No exception thrown when creating safe file with path with null byte.");
            //}
            //catch (ValidationException e)
            //{
            //    // expected
            //}
        }


        // test good file with uri constructor
        public void Test_CreateSafeFileURIConstructor()
        {
            Console.Out.WriteLine("SafeFile URI constructor");
            try
            {
                String goodFileName = Esapi.SecurityConfiguration().ResourceDirectory + "/ESAPI.properties";
                FileInfo goodFile = new SafeFile(new Uri("file:///" + goodFileName)).SafeFileInfo;
                Assert.IsTrue(goodFile.Exists);
            }
            catch (Exception e)
            {
                // pass
            }

            // test uri constructor with null byte
            try
            {
                new SafeFile(new Uri("file:///test" + (char)0 + ".xml"));
                Assert.Fail("No exception thrown when creating a Safe File through a URI with a null byte");
            }
            catch (Exception e)
            {
                // pass
            }

            // test http uri
            try
            {
                new SafeFile(new Uri("http://localserver/test" + (char)0 + ".xml"));
                Assert.Fail("No exception thrown when creating a Safe File through a URI with a null byte");
            }
            catch (Exception e)
            {
                // pass
            }
        }
        
        static public String ToHex(byte b)
        {
            char[] hexDigit = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            char[] array = { hexDigit[(b >> 4) & 0x0f], hexDigit[b & 0x0f] };
            return new String(array);
        }	
        
    }
}