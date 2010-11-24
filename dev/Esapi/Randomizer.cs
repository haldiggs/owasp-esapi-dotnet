using System;
using System.Security.Cryptography;
using System.Text;
using Owasp.Esapi.Errors;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.IRandomizer" />
    /// <summary> Reference implemenation of the <see cref="Owasp.Esapi.IRandomizer" /> interface. This implementation builds on the MSCAPI provider to provide a
    /// cryptographically strong source of entropy. The specific algorithm used is configurable in the ESAPI properties.
    /// </summary>
    public class Randomizer : IRandomizer
    {
        private RandomNumberGenerator randomNumberGenerator = null;

        /// <summary>
        /// Instantiates the class, with the apropriate algorithm.
        /// </summary>
        public Randomizer()
        {
            string algorithm = Esapi.SecurityConfiguration.RandomAlgorithm;
            try
            {
                randomNumberGenerator = RandomNumberGenerator.Create(algorithm);
            }
            catch (Exception e)
            {
                throw new EncryptionException(EM.Randomizer_Failure, string.Format(EM.Randomizer_AlgCreateFailed1, algorithm), e);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.IRandomizer.GetRandomBoolean()" />
        public bool GetRandomBoolean()
        {        
            byte[] randomByte = new byte[1];
            randomNumberGenerator.GetBytes(randomByte);
            return (randomByte[0] >= 128);
            
        }
        
        /// <inheritdoc cref="Owasp.Esapi.IRandomizer.GetRandomGUID()" />
        public Guid GetRandomGUID()
        {
            string guidString = string.Format("{0}-{1}-{2}-{3}-{4}",
                                        GetRandomString(8, CharSetValues.Hex),
                                        GetRandomString(4, CharSetValues.Hex),
                                        GetRandomString(4, CharSetValues.Hex),
                                        GetRandomString(4, CharSetValues.Hex),
                                        GetRandomString(12, CharSetValues.Hex));
            return new Guid(guidString);

        }

        /// <inheritdoc cref="Owasp.Esapi.IRandomizer.GetRandomString(int, char[])" />
        public string GetRandomString(int length, char[] characterSet)
        {
            StringBuilder sb = new StringBuilder();

            for (int loop = 0; loop < length; loop++)
            {                
                int index = GetRandomInteger(0, characterSet.GetLength(0) - 1);
                sb.Append(characterSet[index]);                
            }
            string nonce = sb.ToString();
            return nonce;
        }
        
        /// <inheritdoc cref="Owasp.Esapi.IRandomizer.GetRandomInteger(int, int)" />
        public int GetRandomInteger(int min, int max)
        {           
            double range = (double) max - min;
            byte[] randomBytes = new byte[sizeof(int)];
            randomNumberGenerator.GetBytes(randomBytes);
            uint randomFactor = BitConverter.ToUInt32(randomBytes, 0);
            double divisor = (double) randomFactor / UInt32.MaxValue;
            int randomNumber = Convert.ToInt32(Math.Round(range * divisor) + min);
            return randomNumber;
        }

        /// <inheritdoc cref="Owasp.Esapi.IRandomizer.GetRandomDouble(double, double)" />
        public double GetRandomDouble(double min, double max)
        {
            // This method only gives you 32 bits of entropy (based of random int).
            double factor = max - min;
            double random = (double) GetRandomInteger(0, Int32.MaxValue) / (double) Int32.MaxValue;
            return random * factor + min;
        }

        /// <inheritdoc cref="Owasp.Esapi.IRandomizer.GetRandomFilename(string)" />
        public string GetRandomFilename(string extension)
        {
            return this.GetRandomString(12, CharSetValues.Alphanumerics) + "." + extension;
        }

        static bool Contains(StringBuilder sb, char c)
        {            
            for (int i = 0; i < sb.Length; i++)
            {
                if (sb[i] == c)
                    return true;
            }
            return false;
        }
    }
}
