using System;
using System.Security.Cryptography;
using System.Text;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.IRandomizer" />
    /// <remarks> Reference implemenation of the IRandomizer interface. This implementation builds on the MSCAPI provider to provide a
    /// cryptographically strong source of entropy. The specific algorithm used is configurable in Esapi.properties.
    /// </remarks>
    public class Randomizer : IRandomizer
    {
        private RandomNumberGenerator randomNumberGenerator = null;

        private static readonly ILogger logger;
        private static char[] CHARS_HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

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
                new EncryptionException("Error creating randomizer", "Can't find random algorithm " + algorithm, e);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomBoolean()" />
        public bool GetRandomBoolean()
        {        
            byte[] randomByte = new byte[1];
            randomNumberGenerator.GetBytes(randomByte);
            return (randomByte[0] >= 128);
            
        }
        
        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomGUID()" />
        public Guid GetRandomGUID()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(GetRandomString(8, CHARS_HEX));
            sb.Append("-");
            sb.Append(GetRandomString(4, CHARS_HEX));
            sb.Append("-");
            sb.Append(GetRandomString(4, CHARS_HEX));
            sb.Append("-");
            sb.Append(GetRandomString(4, CHARS_HEX));
            sb.Append("-");
            sb.Append(GetRandomString(12, CHARS_HEX));
            return new Guid(sb.ToString());

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomString(int, char[])" />
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
        
        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomInteger(int, int)" />
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

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomDouble(double, double)" />
        public double GetRandomDouble(double min, double max)
        {
            // This method only gives you 32 bits of entropy (based of random int).
            double factor = max - min;
            double random = (double) GetRandomInteger(0, Int32.MaxValue) / (double) Int32.MaxValue;
            return random * factor + min;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomFilename(string)" />
        public string GetRandomFilename(string extension)
        {
            return this.GetRandomString(12, Encoder.CHAR_ALPHANUMERICS) + "." + extension;
        }

        static char[] Union(char[] c1, char[] c2)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < c1.Length; i++)
            {
                if (!Contains(sb, c1[i]))
                    sb.Append(c1[i]);
            }
            for (int i = 0; i < c2.Length; i++)
            {
                if (!Contains(sb, c2[i]))
                    sb.Append(c2[i]);
            }
            char[] c3 = new char[sb.Length];
            int i2;
            int j;
            i2 = 0;
            j = 0;
            while (i2 < sb.Length)
            {
                c3[j] = sb[i2];
                i2++;
                j++;
            }
            Array.Sort(c3);
            return c3;
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
        
        /// <summary>
        /// Static constuctor
        /// </summary>
        static Randomizer()
        {
            logger = Esapi.Logger;
        }
    }
}
