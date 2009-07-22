using System;
namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    ///  The Codec interface defines a set of methods for encoding and decoding application level encoding schemes, 
    ///  such as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding  
    ///  and canonicalization.  The design of these codecs allows for character-by-character decoding, which is  
    ///  necessary to detect double-encoding and the use of multiple encoding schemes, both of which are techniques  
    ///  used by attackers to bypass validation and bury encoded attacks in data. 
    /// </summary>
    public interface ICodec
    {
        /// <summary>
        /// Decode a String that was encoded using the encode method in this Class
        /// </summary>
        /// <param name="input">The string to decode</param>
        /// <returns>The decoded string</returns> 
        string Encode(string input);
        
        /// <summary>
        /// Decode a String that was encoded using the encode method in this Class
        /// </summary>
        /// <param name="input">The string to decode</param>
        /// <returns>The decoded string</returns> 
        string Decode(string input);
    }
}
