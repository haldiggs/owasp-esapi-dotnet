using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Configuration;
using Rhino.Mocks;
using EsapiTest.Surrogates;

namespace EsapiTest
{

    /// <summary> The Class EncryptorTest.
    /// 
    /// </summary>
    [TestClass]
    public class EncryptorTest
    {      
        [TestInitialize]
        public void InitializeTest()
        {
            Esapi.Reset();
            EsapiConfig.Reset();
        }
        
        /// <summary> Test of Hash method, of class Owasp.Esapi.Encryptor.</summary>
        [TestMethod]
        public void Test_Hash()
        {
            System.Console.Out.WriteLine("hash");
            IEncryptor encryptor = Esapi.Encryptor;
            string hash1 = encryptor.Hash("test1", "salt");
            string hash2 = encryptor.Hash("test2", "salt");
            Assert.IsFalse(hash1.Equals(hash2));
            String hash3 = encryptor.Hash("test", "salt1");
            String hash4 = encryptor.Hash("test", "salt2");
            Assert.IsFalse(hash3.Equals(hash4));
        }

        /// <summary> Test of Encrypt method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [TestMethod]
        public void Test_Encrypt()
        {
            System.Console.Out.WriteLine("Encrypt");
            IEncryptor encryptor = Esapi.Encryptor;
            string plaintext = "test123";
            string ciphertext = encryptor.Encrypt(plaintext);
            string result = encryptor.Decrypt(ciphertext);
            Assert.AreEqual(plaintext, result);
        }

        /// <summary> Test of decrypt method, of class Owasp.Esapi.Encryptor.</summary>
        [TestMethod]
        public void Test_Decrypt()
        {
            System.Console.Out.WriteLine("decrypt");
            IEncryptor encryptor = Esapi.Encryptor;
            try
            {
                string plaintext = "test123";
                string ciphertext = encryptor.Encrypt(plaintext);
                Assert.IsFalse(plaintext.Equals(ciphertext));
                string result = encryptor.Decrypt(ciphertext);
                Assert.AreEqual(plaintext, result);
            }
            catch (EncryptionException)
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

        [TestMethod]
        public void Test_Sign()
        {
            System.Console.Out.WriteLine("Sign");
            IEncryptor encryptor = Esapi.Encryptor;
            string plaintext = Esapi.Randomizer.GetRandomString(32, Owasp.Esapi.CharSetValues.Alphanumerics);
            string signature = encryptor.Sign(plaintext);
            Assert.IsTrue(encryptor.VerifySignature(signature, plaintext));
            Assert.IsFalse(encryptor.VerifySignature(signature, "ridiculous"));
            Assert.IsFalse(encryptor.VerifySignature("ridiculous", plaintext));
        }

        /// <summary> Test of VerifySignature method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>

        [TestMethod]
        public void Test_VerifySignature()
        {
            System.Console.Out.WriteLine("verifySignature");
            IEncryptor encryptor = Esapi.Encryptor;
            string plaintext = Esapi.Randomizer.GetRandomString(32, Owasp.Esapi.CharSetValues.Alphanumerics);
            string signature = encryptor.Sign(plaintext);
            Assert.IsTrue(encryptor.VerifySignature(signature, plaintext));
        }


        /// <summary> Test of Seal method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [TestMethod]
        public void Test_Seal()
        {
            System.Console.Out.WriteLine("seal");
            IEncryptor encryptor = Esapi.Encryptor;
            string plaintext = Esapi.Randomizer.GetRandomString(32, Owasp.Esapi.CharSetValues.Alphanumerics);
            string seal = encryptor.Seal(plaintext, encryptor.TimeStamp + 1000 * 60);
            encryptor.VerifySeal(seal);
        }

        /// <summary> Test of VerifySeal method, of class Owasp.Esapi.Encryptor.
        /// 
        /// </summary>
        /// <throws>  EncryptionException </throws>
        /// <summary>             the encryption exception
        /// </summary>
        [TestMethod]
        public void Test_VerifySeal()
        {
            System.Console.Out.WriteLine("verifySeal");
            IEncryptor encryptor = Esapi.Encryptor;
            string plaintext = Esapi.Randomizer.GetRandomString(32, Owasp.Esapi.CharSetValues.Alphanumerics);
            string seal = encryptor.Seal(plaintext, encryptor.TimeStamp + 1000 * 60);
            Assert.IsTrue(encryptor.VerifySeal(seal));
            Assert.IsFalse(encryptor.VerifySeal("ridiculous"));
            Assert.IsFalse(encryptor.VerifySeal(encryptor.Encrypt("ridiculous")));
            Assert.IsFalse(encryptor.VerifySeal(encryptor.Encrypt(100 + ":" + "ridiculous")));
            Assert.IsTrue(encryptor.VerifySeal(encryptor.Encrypt(long.MaxValue + ":" + "ridiculous")));                        
        }


        /// <summary> Test of decrypt method, of class Owasp.Esapi.Encryptor.</summary>
        [TestMethod]
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

            catch (EncryptionException)
            {
                Assert.Fail();
            }
        }

        [TestMethod]
        public void Test_LoadCustom()
        {
            MockRepository mocks = new MockRepository();

            // Set new encryptor
            EsapiConfig.Instance.Encryptor.Type = typeof(SurrogateEncryptor).AssemblyQualifiedName;

            IEncryptor encryptor = Esapi.Encryptor;
            Assert.IsTrue(encryptor.GetType().Equals(typeof(SurrogateEncryptor)));

            // Do some calls
            IEncryptor mockEncryptor = mocks.StrictMock<IEncryptor>();
            ((SurrogateEncryptor)encryptor).Impl = mockEncryptor;

            Expect.Call(mockEncryptor.VerifySeal(null)).Return(true);
            Expect.Call(mockEncryptor.Seal(null, 0)).Return(null);
            mocks.ReplayAll();

            Assert.IsTrue(encryptor.VerifySeal(null));
            Assert.IsNull(encryptor.Seal(null, 0));
            mocks.VerifyAll();            
        }
    }
}
