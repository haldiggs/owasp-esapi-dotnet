using Owasp.Esapi.Interfaces;

namespace EsapiTest.Surrogates
{
    /// <summary>
    /// Forward encryptor for mocking
    /// </summary>
    internal class SurrogateEncryptor : IEncryptor
    {
        public IEncryptor Impl { get; set; }
        #region IEncryptor Members

        public long TimeStamp
        {
            get { return Impl.TimeStamp; }
        }

        public string Hash(string plaintext, string salt)
        {
            return Impl.Hash(plaintext, salt);
        }

        public string Encrypt(string plaintext)
        {
            return Impl.Encrypt(plaintext);
        }

        public string Decrypt(string ciphertext)
        {
            return Impl.Decrypt(ciphertext);
        }

        public string Sign(string data)
        {
            return Impl.Sign(data);
        }

        public bool VerifySignature(string signature, string data)
        {
            return Impl.VerifySignature(signature, data);
        }

        public string Seal(string data, long timestamp)
        {
            return Impl.Seal(data, timestamp);
        }

        public string Unseal(string seal)
        {
            return Impl.Unseal(seal);
        }

        public bool VerifySeal(string seal)
        {
            return Impl.VerifySeal(seal);
        }

        #endregion
    }
}
