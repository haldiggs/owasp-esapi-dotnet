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
        
        /// <summary>
        /// The symmetric key
        /// </summary>
        private byte[] secretKey;


        /// <summary>The asymmetric key pair </summary>
        internal CspParameters asymmetricKeyPair;

        /// <summary>The logger. </summary>
        private static readonly ILogger logger;

        // FIXME: AAA need global scrub of what methods need to log

        internal string encryptAlgorithm = Esapi.SecurityConfiguration.EncryptionAlgorithm;
        internal string signatureAlgorithm = "DSA";// TODO Add Esapi.SecurityConfiguration.SignatureAlgorithm;
        internal string hashAlgorithm = Esapi.SecurityConfiguration.HashAlgorithm;
        internal string randomAlgorithm = Esapi.SecurityConfiguration.RandomAlgorithm;
        internal string encoding = "UTF-8"; //TODO Add Esapi.SecurityConfiguration.Encoding;
        
        /// <summary>
        /// Public constructor.
        /// </summary>
        public Encryptor()
        {
            string pass = Esapi.SecurityConfiguration.MasterPassword;
            byte[] salt = Esapi.SecurityConfiguration.MasterSalt;            

            encryptAlgorithm = Esapi.SecurityConfiguration.EncryptionAlgorithm;            
            signatureAlgorithm = Esapi.SecurityConfiguration.DigitalSignatureAlgorithm;
            randomAlgorithm = Esapi.SecurityConfiguration.RandomAlgorithm;
            hashAlgorithm = Esapi.SecurityConfiguration.HashAlgorithm;
            encoding = Esapi.SecurityConfiguration.CharacterEncoding;
            try
            {
                

                // Set up encryption and decryption                
                SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.Create(encryptAlgorithm);
                Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(pass, salt);
                secretKey = rfc2898.GetBytes(symmetricAlgorithm.KeySize / 8);
                
                
                // 13 is the code for DSA
                asymmetricKeyPair = new CspParameters(13);
                // The asymmetric key will be stored in the key container using the name ESAPI.
                asymmetricKeyPair.KeyContainerName = "ESAPI";
                
                RandomNumberGenerator randomNumberGenerator = RNGCryptoServiceProvider.Create(randomAlgorithm);                
            }
            catch (Exception e)
            {                
                throw new EncryptionException("Encryption failure", "Error creating Encryptor", e);
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
                byte[] originalBytes = Encoding.UTF8.GetBytes(plaintext + salt);

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
                symmetricAlgorithm.GenerateIV();
                byte[] iv = symmetricAlgorithm.IV;
                
                ICryptoTransform encryptor = symmetricAlgorithm.CreateEncryptor(secretKey, iv);
                // Define a new CryptoStream object to hold the encrypted bytes
                // and encrypt the data.
                MemoryStream msEncrypt = new MemoryStream();
                CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                try
                {                    
                    // Convert the data to a byte array.
                    Encoding textConverter = Encoding.GetEncoding(encoding);
                    byte[] plaintextBytes = textConverter.GetBytes(plaintext);
                    // Encrypt the data by writing it to the CryptoStream object.
                    // Write all data to the crypto stream and flush it.
                    csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                    csEncrypt.FlushFinalBlock();

                    // Get encrypted array of bytes from the memory stream.
                    byte[] encryptedBytes = msEncrypt.ToArray();
                    byte[] encryptedBytesPlusIv = Combine(iv, encryptedBytes);
                    return Convert.ToBase64String(encryptedBytesPlusIv);
                } finally
                {                    
                    symmetricAlgorithm.Clear();
                    msEncrypt.Close();
                    csEncrypt.Close();
                }                
            }
            catch (Exception e)
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
                
                byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);

                // Ciphertext actually includes the IV, so we need to split it out
                // Get first part of array, which is IV
                int ivLength = symmetricAlgorithm.IV.Length;
                byte[] ivBytes = new byte[ivLength];
                Array.Copy(ciphertextBytes, ivBytes, ivLength);
                
                // Get second part of array which is actual ciphertext
                int onlyCiphertextLength = ciphertextBytes.Length - ivLength;
                byte[] onlyCiphertextBytes = new byte[onlyCiphertextLength];
                Array.Copy(ciphertextBytes, ivLength, onlyCiphertextBytes, 0, onlyCiphertextLength);
                
                ICryptoTransform decryptor = symmetricAlgorithm.CreateDecryptor(secretKey, ivBytes);
                
                // Now decrypt the previously encrypted data using the decryptor.
                MemoryStream msDecrypt = new MemoryStream(onlyCiphertextBytes);
                CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                try
                {
                
                    // Read the data out of the crypto stream.
                    byte[] plaintextBytes = new byte[onlyCiphertextLength];
                    int decryptedBytes = csDecrypt.Read(plaintextBytes, 0, onlyCiphertextLength);

                    // Convert the byte array back into a string.
                    Encoding textConverter = Encoding.GetEncoding(encoding);
                    string plaintext = textConverter.GetString(plaintextBytes, 0, decryptedBytes);
                    return plaintext;
                } finally
                {
                    symmetricAlgorithm.Clear();
                    msDecrypt.Close();
                    csDecrypt.Close();
                }
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
                // Since this is the only asymmetric algorithm with signing capabilities, its hardcoded.
                // The more general APIs just aren't friendly.
                DSACryptoServiceProvider dsaCsp = new DSACryptoServiceProvider(asymmetricKeyPair);
                Encoding textConverter = Encoding.GetEncoding(encoding);
                byte[] dataBytes = textConverter.GetBytes(data);
                byte[] signatureBytes = dsaCsp.SignData(dataBytes);
                bool valid = dsaCsp.VerifyData(dataBytes, signatureBytes);
                return Esapi.Encoder.EncodeForBase64(signatureBytes);
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
                byte[] signatureBytes = Esapi.Encoder.DecodeFromBase64(signature);
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

        public String Unseal(String seal)
        {
            String plaintext = null;
            try
            {
                plaintext = Decrypt(seal);
            }
            catch (EncryptionException e)
            {
                throw new EncryptionException("Invalid seal", "Seal did not decrypt properly", e);
            }

            int index = plaintext.IndexOf(":");
            if (index == -1)
            {
                throw new EncryptionException("Invalid seal", "Seal did not contain properly formatted separator");
            }

            String timestring = plaintext.Substring(0, index);
            long now = DateTime.Now.Ticks;
            long expiration = Convert.ToInt64(timestring);
            if (now > expiration)
            {
                throw new EncryptionException("Invalid seal", "Seal expiration date has expired");
            }

            index = plaintext.IndexOf(":", index + 1);
            String sealedValue = plaintext.Substring(index + 1);
            return sealedValue;
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
        public bool VerifySeal(string seal)
        {
            try
            {
                Unseal(seal);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private byte[] Combine(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, c, 0, a.Length);
            Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
            return c;
        }

        
        static Encryptor()
        {
            logger = Esapi.Logger;
        }
    }
}
