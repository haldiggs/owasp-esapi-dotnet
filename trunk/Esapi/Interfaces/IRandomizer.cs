using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IRandomizer interface defines a set of methods for creating
    /// cryptographically random numbers and strings. Implementers should be sure to
    /// use a strong cryptographic implementation, such as the JCE or BouncyCastle.
    /// Weak sources of randomness can undermine a wide variety of security
    /// mechanisms.
    /// <img src="doc-files/Randomizer.jpg" height="600" />
    /// </summary>    
    public interface IRandomizer
    {
        /// <summary> Returns a random bool.</summary>
        bool GetRandomBoolean(); 
        
            /// <summary> Generates a random GUID.</summary>
        Guid GetRandomGUID();   

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
        string GetRandomString(int length, char[] characterSet);

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
        int GetRandomInteger(int min, int max);

        /// <summary>
        /// Returns an unguessable filename.
        /// </summary>
        /// <param name="extension">The extension for the filename</param>
        /// <returns>The unguessable filename</returns>
        string GetRandomFilename(string extension);

        /// <summary> 
        /// Gets a random double.
        /// 
        /// </summary>
        /// <param name="min">
        /// The minimum value.
        /// </param>
        /// <param name="max">
        /// The maximum value.        
        /// </param>
        /// <returns>
        /// The random double.
        /// </returns>
        double GetRandomDouble(double min, double max);
    }
}
