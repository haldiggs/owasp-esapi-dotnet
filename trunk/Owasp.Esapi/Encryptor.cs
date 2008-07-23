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
using Owasp.Esapi.Interfaces;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi
{

    /// <summary> Reference implementation of the IEncryptor interface. This implementation
    /// layers on the JCE provided cryptographic package. Algorithms used are
    /// configurable in the ESAPI.properties file.
    /// 
    /// 
    /// </summary>
    /// <author> Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor">
    /// </seealso>
    public class Encryptor:IEncryptor
    {
        /// <summary> Gets a timestamp representing the current date and time to be used by
        /// other functions in the library.
        /// 
        /// </summary>
        /// <returns> The timestamp in long format.
        /// </returns>
        public long TimeStamp
        {
            get
            {                
                return System.DateTime.Now.Ticks;
            }

        }
        private byte[] secretKey;
        private byte[] iv;

        /// <summary>The asymmetric key pair </summary>
        internal CspParameters asymmetricKeyPair;

        /// <summary>The logger. </summary>
        private static readonly Logger logger;

        // FIXME: AAA need global scrub of what methods need to log

        internal string encryptAlgorithm = "Rijndael";
        internal string signatureAlgorithm = "DSA";
        internal string hashAlgorithm = "SHA-512";
        internal string randomAlgorithm = "SHA1PRNG";
        internal string encoding = "UTF-8";        
        
        /// <summary>
        /// Public constructor.
        /// </summary>
        public Encryptor()
        {

            // FIXME: AAA - need support for key and salt changing. What's best interface?
            byte[] salt = Esapi.SecurityConfiguration().MasterSalt;
            string pass = Esapi.SecurityConfiguration().MasterPassword;

            // setup algorithms
            encryptAlgorithm = Esapi.SecurityConfiguration().EncryptionAlgorithm;            
            signatureAlgorithm = Esapi.SecurityConfiguration().DigitalSignatureAlgorithm;
            randomAlgorithm = Esapi.SecurityConfiguration().RandomAlgorithm;
            hashAlgorithm = Esapi.SecurityConfiguration().HashAlgorithm;

            try
            {
                // Set up encryption and decryption                
                SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.Create(encryptAlgorithm);
                symmetricAlgorithm.GenerateIV();
                iv = symmetricAlgorithm.IV;
                symmetricAlgorithm.Padding = PaddingMode.PKCS7;

                PasswordDeriveBytes passwordDeriveBytes = new PasswordDeriveBytes(pass, salt);
                // FIXME: We are using SHA1 hardcoded here, because for some reason CryptDeriveKey doesn't 
                // like other hash algorithms. Also, it appears to not like Rijndael as a encryption algorithm.
                secretKey = passwordDeriveBytes.CryptDeriveKey(encryptAlgorithm, "SHA1", symmetricAlgorithm.KeySize, iv);
                encoding = Esapi.SecurityConfiguration().CharacterEncoding;

                // 13 is the code for DSA
                asymmetricKeyPair = new CspParameters(13);

                // The asymmetric key will be stored in the key container using the name ESAPI.
                asymmetricKeyPair.KeyContainerName = "ESAPI";
                // Set up signing keypair using the master password and salt
                // FIXME: Enhance - make DSA configurable
                
                RandomNumberGenerator randomNumberGenerator = RNGCryptoServiceProvider.Create(randomAlgorithm);                
            }
            catch (Exception e)
            {
                // can't throw this exception in initializer, but this will log it
                new EncryptionException("Encryption failure", "Error creating Encryptor", e);
            }
        }

        /// <summary> Hashes the data using the specified algorithm and the SHA1CryptoServiceProvider class. This method
        /// first adds the salt, then the data, and then rehashes 1024 times to help strengthen weak passwords.
        /// </summary>
        /// <param name="plaintext">The plaintext.
        /// </param>
        /// <param name="salt">The salt.        
        /// </param>
        /// <returns>The salted and hashed value.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor.Hash(string, string)">
        /// </seealso>
        public string Hash(string plaintext, string salt)
        {            
            try
            {
                // Create a new instance of the hash crypto service provider.
                // FIXME: Read the value from the SecurityConfiguration.
                HashAlgorithm hasher = HashAlgorithm.Create(hashAlgorithm);

                // Convert the data to hash to an array of Bytes.
                byte[] originalBytes = System.Text.Encoding.UTF8.GetBytes(plaintext + salt);

                // Compute the Hash. This returns an array of Bytes.
                byte[] hashBytes = hasher.ComputeHash(originalBytes);

                // rehash a number of times to help strengthen weak passwords
                // FIXME: ENHANCE make iterations configurable                
                for (int i = 0; i < 1024; i++)
                {
                    hashBytes = hasher.ComputeHash(hashBytes);
                }
                // Optionally, represent the hash value as a base64-encoded string, 
                // For example, if you need to display the value or transmit it over a network.
                string hashBase64String = Convert.ToBase64String(hashBytes);

                return hashBase64String;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Internal error", "Can't find hash algorithm " + hashAlgorithm, e);
            }
        }

        /// <summary> Encrypts the provided plaintext and returns a ciphertext string.        
        /// </summary>
        /// <param name="plaintext">The unencrypted value (plaintext).
        /// </param>
        /// <returns> The encrypted value (ciphertext).
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor.Encrypt(string)">
        /// </seealso>
        public string Encrypt(string plaintext)
        {
            // Note - Cipher is not threadsafe so we create one locally
            try
            {                

                // Create a new key and initialization vector.
                // If a key is not provided, a key of appropriate length is
                // automatically generated. You can retrieve its value through the Key
                // property. Similarly, an initialization vector is automatically
                // generated if you do not specify one.

                // Get the encryptor.
                SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.Create(encryptAlgorithm);
                ICryptoTransform encryptor = symmetricAlgorithm.CreateEncryptor(secretKey, iv);
                // Define a new CryptoStream object to hold the encrypted bytes
                // and encrypt the data.
                MemoryStream msEncrypt = new MemoryStream();
                CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                // Convert the data to a byte array.
                Encoding textConverter = Encoding.GetEncoding(encoding);
                byte[] plaintextBytes = textConverter.GetBytes(plaintext);                
                // Encrypt the data by writing it to the CryptoStream object.
                // Write all data to the crypto stream and flush it.
                csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                csEncrypt.FlushFinalBlock();

                // Get encrypted array of bytes from the memory stream.
                byte[] encryptedBytes = msEncrypt.ToArray();

                return Convert.ToBase64String(encryptedBytes);
            }
            catch (System.Exception e)
            {                
                throw new EncryptionException("Encryption failure", "Decryption problem: " + e.Message, e);
            }
        }

        /// <summary> Decrypts the provided ciphertext string (encrypted with the encrypt
        /// method) and returns a plaintext string.
        /// 
        /// </summary>
        /// <param name="ciphertext">The encrypted value (ciphertext).
        /// </param>
        /// <returns> The unencrypted value (plaintext).
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor.Decrypt(string)">
        /// </seealso>
        public string Decrypt(string ciphertext)
        {
            // Note - Cipher is not threadsafe so we create one locally
            try
            {
                SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.Create(encryptAlgorithm);
                ICryptoTransform decryptor = symmetricAlgorithm.CreateDecryptor(secretKey, iv);
                // Now decrypt the previously encrypted data using the decryptor.
                MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(ciphertext));
                CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                byte[] cleartextBytes = new byte[Convert.FromBase64String(ciphertext).Length];

                // Read the data out of the crypto stream.
                csDecrypt.Read(cleartextBytes, 0, cleartextBytes.Length);

                // Convert the byte array back into a string.
                Encoding textConverter = Encoding.GetEncoding(encoding);
                string plaintext = textConverter.GetString(cleartextBytes);
                return plaintext;
            }
            catch (System.Exception e)
            {                
                throw new EncryptionException("Decryption failed", "Decryption problem: " + e.Message, e);
            }
        }

        /// <summary> Create a digital signature for the provided data and return it in a
        /// string.
        /// </summary>
        /// <param name="data">The data to sign.
        /// </param>
        /// <returns> The signature.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor.Sign(string)">
        /// </seealso>
        public string Sign(string data)
        {          
            try
            {
                DSACryptoServiceProvider dsaCsp = new DSACryptoServiceProvider(asymmetricKeyPair);
                Encoding textConverter = Encoding.GetEncoding(encoding);
                byte[] dataBytes = textConverter.GetBytes(data);
                byte[] signatureBytes = dsaCsp.SignData(dataBytes);
                bool valid = dsaCsp.VerifyData(dataBytes, signatureBytes);
                return Esapi.Encoder().EncodeForBase64(signatureBytes, true);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Signature failure", "Can't find signature algorithm " + signatureAlgorithm, e);
            }
        }


        /// <summary> Verifies a digital signature (created with the sign method) and returns
        /// the boolean result.
        /// </summary>
        /// <param name="signature">The signature to verify.
        /// </param>
        /// <param name="data">The data to verify the signature against.
        /// </param>
        /// <returns> true, if successful
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor.VerifySignature(string, string)">
        /// </seealso>
        public bool VerifySignature(string signature, string data)
        {
            try
            {
                DSACryptoServiceProvider dsaCsp = new DSACryptoServiceProvider(asymmetricKeyPair);
                Encoding textConverter = Encoding.GetEncoding(encoding);
                byte[] signatureBytes = Esapi.Encoder().DecodeFromBase64(signature);
                byte[] dataBytes = textConverter.GetBytes(data);
                
                return dsaCsp.VerifyData(dataBytes, signatureBytes);                
            }
            catch (System.Exception e)
            {                
                new EncryptionException("Invalid signature", "Problem verifying signature: " + e.Message, e);
                return false;
            }
        }

        /// <summary> Creates a seal that binds a set of data and an expiration timestamp.
        /// </summary>
        /// <param name="data">The data to seal.
        /// </param>
        /// <param name="expiration">The timestamp of the expiration date of the data.        
        /// </param>
        /// <returns> The seal value.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor.Seal(string, long)">
        /// </seealso>
        public string Seal(string data, long expiration)
        {
            try
            {
                return this.Encrypt(expiration + ":" + data);
            }
            catch (EncryptionException e)
            {
                throw new IntegrityException(e.UserMessage, e.LogMessage, e);
            }
        }

        /// <summary> Verifies a seal (created with the seal method) and throws an exception
        /// describing any of the various problems that could exist with a seal, such
        /// as an invalid seal format, expired timestamp, or data mismatch.
        /// </summary>
        /// <param name="seal">The seal.
        /// </param>
        /// <param name="data">The data that was sealed.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptor.VerifySeal(string, string)">
        /// </seealso>
        public bool VerifySeal(string seal, string data)
        {
            string plaintext = null;
            try
            {
                plaintext = Decrypt(seal);
            }
            catch (EncryptionException e)
            {
                new EncryptionException("Invalid seal", "Seal did not decrypt properly", e);
                return false;
            }

            int index = plaintext.IndexOf(":");
            if (index == -1)
            {
                new EncryptionException("Invalid seal", "Seal did not contain properly formatted separator");
                return false;
            }

            string timestring = plaintext.Substring(0, (index) - (0));            
            long now = System.DateTime.Now.Ticks;
            long expiration = System.Int64.Parse(timestring);
            if (now > expiration)
            {
                new EncryptionException("Invalid seal", "Seal expiration date has expired");
                return false;
            }

            string sealedValue = plaintext.Substring(index + 1);
            if (!sealedValue.Equals(data))
            {
                new EncryptionException("Invalid seal", "Seal data does not match");
                return false;
            }
            return true;
        }
        static Encryptor()
        {
            logger = Logger.GetLogger("ESAPI", "Encryptor");
        }
    }
}
