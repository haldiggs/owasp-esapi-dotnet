/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/Category:ESAPI.
/// 
/// Copyright (c) 2009 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the BSD. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen
/// </author>
/// <created>  2008 </created>

using System;
using Owasp.Esapi.Interfaces;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Net;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi
{
    /// <summary> Reference implemenation of the IRandomizer interface. This implementation builds on the JCE provider to provide a
    /// cryptographically strong source of entropy. The specific algorithm used is configurable in Esapi.properties.
    /// 
    /// </summary>
    /// <author>  Alex Smolen
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IRandomizer">
    /// </seealso>
    public class Randomizer : IRandomizer
    {
        private RandomNumberGenerator randomNumberGenerator = null;

        private static readonly ILogger logger;
        private static char[] CHARS_HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        /// <summary> Hide the constructor for the Singleton pattern.</summary>
        public Randomizer()
        {
            string algorithm = Esapi.SecurityConfiguration.RandomAlgorithm;
            try
            {
                //Todo: Right now algorithm is ignored
                randomNumberGenerator = RNGCryptoServiceProvider.Create();
            }
            catch (Exception e)
            {
                // Can't throw an exception from the constructor, but this will get
                // it logged and tracked
                new EncryptionException("Error creating randomizer", "Can't find random algorithm " + algorithm, e);
            }
        }

        /// <summary> Returns a random bool.</summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IRandomizer.Randombool">
        /// </seealso>
        public bool GetRandomBoolean()
        {        
            byte[] randomByte = new byte[1];
            randomNumberGenerator.GetBytes(randomByte);
            return (randomByte[0] >= 128);
            
        }
        /// <summary> Generates a random GUID.</summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IRandomizer.RandomGUID">
        /// </seealso>
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

        /// <summary> 
        /// Gets a random string.
        /// </summary>
        /// <param name="length">
        /// The desired length.
        /// </param>
        /// <param name="characterSet">
        /// The desired character set.
        /// </param>
        /// <returns> The random string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomString(int, char[])">
        /// </seealso>
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


        /// <summary> 
        /// Gets a random integer.        
        /// </summary>
        /// <param name="min">
        /// The minimum value.
        /// </param>
        /// <param name="max">
        /// The maximum value.        
        /// </param>
        /// <returns> 
        /// The random integer
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomInteger(int, int)">
        /// </seealso>
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
        
        /// <summary> 
        /// Gets a random double
        /// </summary>
        /// <param name="min">
        /// The minimum value.
        /// </param>
        /// <param name="max">
        /// The maximum value.        
        /// </param>
        /// <returns>
        /// The random double
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomDouble(double, double)">
        /// </seealso>
        public double GetRandomDouble(double min, double max)
        {
            // TODO: This method only gives you 32 bits of entropy (based of random int). Could figure
            // out the math to give you a full double's worth of entropy. Sorry!
            double factor = max - min;
            double random = (double) GetRandomInteger(0, Int32.MaxValue) / (double) Int32.MaxValue;
            return random * factor + min;            
        }

        /// <summary>
        /// Returns an unguessable filename.
        /// </summary>
        /// <param name="extension">The extension for the filename</param>
        /// <returns>The unguessable filename</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IRandomizer.GetRandomFilename(string)">
        /// </seealso>
        public string GetRandomFilename(string extension)
        {
            return this.GetRandomString(12, Encoder.CHAR_ALPHANUMERICS) + "." + extension;
        }

        /// <summary> Union two character arrays.
        /// </summary>
        /// <param name="c1">The first character array.
        /// </param>
        /// <param name="c2">The second character array.
        /// </param>
        /// <returns> The union of the two charater arrays.
        /// </returns>
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

        /// <summary> Determines if a string buffer contains a char
        /// 
        /// </summary>
        /// <param name="sb">The string buffer.
        /// </param>
        /// <param name="c">The char.
        /// </param>
        /// <returns> true, if found.
        /// </returns>
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
