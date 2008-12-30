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
/// 
using System;
using NUnit.Framework;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class EncryptorTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class EncryptorTest
    {

        /// <summary> Instantiates a new encryptor test.
        /// 
        /// </summary>
        public EncryptorTest():this(null)
        {
        }
        
        /// <summary> Instantiates a new encryptor test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public EncryptorTest(string testName)            
        {
        }

        /// <summary> Test of Hash method, of class Owasp.Esapi.Encryptor.</summary>
        [Test]
        public void Test_Hash()
        {
            System.Console.Out.WriteLine("hash");
            IEncryptor encryptor = Esapi.Encryptor();
            string hash1 = encryptor.Hash("test1", "salt");
            string hash2 = encryptor.Hash("test2", "salt");
            Assert.IsFalse(hash1.Equals(hash2));
        }

        /// <summary> Test of Encrypt method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [Test]
        public void Test_Encrypt()
        {
            System.Console.Out.WriteLine("Encrypt");
            IEncryptor encryptor = Esapi.Encryptor();
            string plaintext = "test123";
            string ciphertext = encryptor.Encrypt(plaintext);
            string result = encryptor.Decrypt(ciphertext);
            Assert.AreEqual(plaintext, result);
        }

        /// <summary> Test of decrypt method, of class Owasp.Esapi.Encryptor.</summary>
        [Test]
        public void Test_Decrypt()
        {
            System.Console.Out.WriteLine("decrypt");
            IEncryptor encryptor = Esapi.Encryptor();
            try
            {
                string plaintext = "test123";
                string ciphertext = encryptor.Encrypt(plaintext);
                Assert.IsFalse(plaintext.Equals(ciphertext));
                string result = encryptor.Decrypt(ciphertext);
                Assert.AreEqual(plaintext, result);
            }
            catch (EncryptionException e)
            {
                Assert.Fail();
            }
        }

        /// <summary> Test of Sign method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        
        [Test]
        public void Test_Sign()
        {
            System.Console.Out.WriteLine("Sign");
            IEncryptor encryptor = Esapi.Encryptor();
            string plaintext = Esapi.Randomizer().GetRandomString(32, Encoder.CHAR_ALPHANUMERICS);
            string signature = encryptor.Sign(plaintext);
            Assert.IsTrue(encryptor.VerifySignature(signature, plaintext));
        }

        /// <summary> Test of VerifySignature method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        
        [Test]
        public void Test_VerifySignature()
        {
            System.Console.Out.WriteLine("verifySignature");
            IEncryptor encryptor = Esapi.Encryptor();
            string plaintext = Esapi.Randomizer().GetRandomString(32, Encoder.CHAR_ALPHANUMERICS);
            string signature = encryptor.Sign(plaintext);
            Assert.IsTrue(encryptor.VerifySignature(signature, plaintext));
        }


        /// <summary> Test of Seal method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [Test]
        public void Test_Seal()
        {
            System.Console.Out.WriteLine("seal");
            IEncryptor encryptor = Esapi.Encryptor();
            string plaintext = Esapi.Randomizer().GetRandomString(32, Encoder.CHAR_ALPHANUMERICS);
            string seal = encryptor.Seal(plaintext, encryptor.TimeStamp + 1000 * 60);
            encryptor.VerifySeal(seal, plaintext);
        }

        /// <summary> Test of VerifySeal method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [Test]
        public void Test_VerifySeal()
        {
            System.Console.Out.WriteLine("verifySeal");
            IEncryptor encryptor = Esapi.Encryptor();
            string plaintext = Esapi.Randomizer().GetRandomString(32, Encoder.CHAR_ALPHANUMERICS);
            string seal = encryptor.Seal(plaintext, encryptor.TimeStamp + 1000 * 60);
            encryptor.VerifySeal(seal, plaintext);
            try
            {
                encryptor.VerifySeal("ridiculous", plaintext);
            }
            catch (EncryptionException e)
            {
                // expected
            }
            try
            {
                string encrypted = encryptor.Encrypt("ridiculous");
                encryptor.VerifySeal(encrypted, plaintext);
            }
            catch (EncryptionException e)
            {
                // expected
            }
            try
            {
                string encrypted = encryptor.Encrypt(100 + ":" + "ridiculous");
                encryptor.VerifySeal(encrypted, plaintext);
            }
            catch (EncryptionException e)
            {
                // expected
            }
            try
            {
                string encrypted = encryptor.Encrypt(System.Int64.MaxValue + ":" + "ridiculous");
                encryptor.VerifySeal(encrypted, plaintext);
            }
            catch (EncryptionException e)
            {
                // expected
            }
        }


        /// <summary> Test of decrypt method, of class Owasp.Esapi.Encryptor.</summary>
        [Test]
        public void Test_MulitpleInstances()
        {
            System.Console.Out.WriteLine("multiple instances");
            IEncryptor encryptor1 = new Encryptor();
            IEncryptor encryptor2 = new Encryptor();
            IEncryptor decryptor1 = new Encryptor();
            IEncryptor decryptor2 = new Encryptor();
            
            try
            {
                string plaintext = "test123";
                string ciphertext1 = encryptor1.Encrypt(plaintext);
                string ciphertext2 = encryptor2.Encrypt(plaintext);
                Assert.AreNotEqual(ciphertext1, ciphertext2);
                string plaintext1 = decryptor1.Decrypt(ciphertext1);
                string plaintext2 = decryptor2.Decrypt(ciphertext2);
                Assert.AreEqual(plaintext1, plaintext2);
            }
            
            catch (EncryptionException e)
            {
                Assert.Fail();
            }
        }
        
    }
}
