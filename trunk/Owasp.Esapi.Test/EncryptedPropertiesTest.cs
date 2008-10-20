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
using System.IO;
using System.Collections;

namespace Owasp.Esapi.Test
{

    /// <summary> The Class EncryptedPropertiesTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class EncryptedPropertiesTest
    {

        /// <summary> Instantiates a new encrypted properties test.
        /// 
        /// </summary>
        public EncryptedPropertiesTest():this(null)
        {
        }

        /// <summary> Instantiates a new encrypted properties test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public EncryptedPropertiesTest(string testName)            
        {
        }
        /// <summary> Test of GetProperty method, of class Owasp.Esapi.EncryptedProperties.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [Test]
        public void Test_GetProperty()
        {
            System.Console.Out.WriteLine("GetProperty");
            EncryptedProperties encryptedProperties = new EncryptedProperties();
            string name = "name";
            string value = "value";
            encryptedProperties.SetProperty(name, value);
            string result = encryptedProperties.GetProperty(name);
            Assert.AreEqual(value, result);
            try
            {
                encryptedProperties.GetProperty("ridiculous");
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
        }

        /// <summary> Test of SetProperty method, of class Owasp.Esapi.EncryptedProperties.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [Test]
        public void Test_SetProperty()
        {
            System.Console.Out.WriteLine("SetProperty");
            EncryptedProperties encryptedProperties = new EncryptedProperties();
            string name = "name";
            string value = "value";
            encryptedProperties.SetProperty(name, value);
            string result = encryptedProperties.GetProperty(name);
            Assert.AreEqual(value, result);
            try
            {
                encryptedProperties.SetProperty(null, null);
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
        }


        /// <summary> Test of KeySet method, of class Owasp.Esapi.EncryptedProperties.</summary>
        [Test]
        public void Test_KeySet()
        {
            System.Console.Out.WriteLine("KeySet");
            EncryptedProperties encryptedProperties = new EncryptedProperties();
            encryptedProperties.SetProperty("one", "two");
            encryptedProperties.SetProperty("two", "three");

            IEnumerator i = encryptedProperties.KeySet().GetEnumerator();
            i.MoveNext();
            Assert.AreEqual("one", (string)i.Current);
            i.MoveNext();
            Assert.AreEqual("two", (string)i.Current);

            try
            {
                i.MoveNext();
                Object o = i.Current;
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
        }

        /// <summary> Test of Store method, of class Owasp.Esapi.EncryptedProperties.</summary>
        [Test]
        public void Test_Store()
        {
            System.Console.Out.WriteLine("Store");
            EncryptedProperties encryptedProperties = new EncryptedProperties();
            encryptedProperties.SetProperty("one", "two");
            encryptedProperties.SetProperty("two", "three");
            String ResourceDirectory = ((SecurityConfiguration)Esapi.SecurityConfiguration()).ResourceDirectory.FullName;
            FileInfo fileRead = new FileInfo(ResourceDirectory + "\\" + "test.properties");
            encryptedProperties.Store(new FileStream(fileRead.FullName, FileMode.Create), "TestStore");

            System.Console.Out.WriteLine("Load");
            encryptedProperties = new EncryptedProperties();            
            FileInfo fileLoad = new FileInfo(ResourceDirectory + "\\" + "test.properties");
            encryptedProperties.Load(new FileStream(fileLoad.FullName, FileMode.Open, FileAccess.Read));
            Assert.AreEqual("two", encryptedProperties.GetProperty("one"));
            Assert.AreEqual("three", encryptedProperties.GetProperty("two"));
        
        }


        /// <summary> Test of Load method, of class Owasp.Esapi.EncryptedProperties.</summary>
        [Test]
        public void Test_Load()
        {

        }

        /// <summary> Test of Main method, of class Owasp.Esapi.EncryptedProperties.</summary>
        [Test]
        public void Test_Main()
        {
            System.Console.Out.WriteLine("Main");
            String ResourceDirectory = ((SecurityConfiguration)Esapi.SecurityConfiguration()).ResourceDirectory.FullName;
            FileInfo f = new FileInfo(ResourceDirectory + "\\" + "test.properties");
            string[] args1 = new string[] { f.FullName };
            Stream orig = System.Console.OpenStandardInput();
            string input = "key\r\nvalue\r\n";
            System.Console.SetIn(new StringReader(input));
            EncryptedProperties.Main(args1);
            string[] args2 = new string[] { "ridiculous.properties" };
            try
            {
                EncryptedProperties.Main(args2);
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
        }

    }



}
