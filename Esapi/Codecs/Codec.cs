using System;
using System.Text;

namespace Owasp.Esapi.Codecs
{
    /// <summary>
    ///  The Codec interface defines a set of methods for encoding and decoding application level encoding schemes, 
    ///  such as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding  
    ///  and canonicalization.  The design of these codecs allows for character-by-character decoding, which is  
    ///  necessary to detect double-encoding and the use of multiple encoding schemes, both of which are techniques  
    ///  used by attackers to bypass validation and bury encoded attacks in data. 
    /// </summary>
    public abstract class Codec
    {                        
        /// <summary>
        /// Default constructor
        /// </summary> 
        public Codec()
        {
        }
        
        /// <summary>
        /// Encode a String so that it can be safely used in a specific context.
        /// </summary>
        /// <param name="immune">The characters which are not supposed to be encoded</param>
        /// <param name="input">The string to encode</param>
        /// <returns>The encoded string</returns>
        public String Encode(char[] immune, string input) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < input.Length; i++) {
                    char c = input[i];
                    sb.Append(EncodeCharacter(immune, c));
                }
                return sb.ToString();
            }
        
        /// <summary>
        /// Default implementation that should be overridden in specific codecs.
        /// </summary>
        /// <param name="immune">The characters which are not supposed to be encoded</param>
        /// <param name="c">The char to encode</param>
        /// <returns>The encoded string</returns>
        public String EncodeCharacter(char[] immune, char c)
        {
            return "" + c;
        }
        
        /// <summary>
        /// Decode a String that was encoded using the encode method in this Class
        /// </summary>
        /// <param name="input">The string to decode</param>
        /// <returns>The decoded string</returns>
 
        public String Decode(String input)
        {
            StringBuilder sb = new StringBuilder();
            PushbackString pbs = new PushbackString(input);
            while (pbs.HasNext)
            {
                char? c = DecodeCharacter(pbs);
                if (c != null)
                {
                    sb.Append(c);
                }
                else
                {
                    sb.Append(pbs.Next());
                }
            }
            return sb.ToString();
        }

        
        /// <summary>
        ///  Returns the decoded version of the next character from the input string and advances the
        /// current character in the PushbackString.  If the current character is not encoded, this 
        /// method MUST reset the PushbackString.         
        /// </summary>
        /// <param name="input">The PushBack string that is used to process the data to decode</param>
        /// <returns>The decoded character, or null if there is no character</returns>
        public char? DecodeCharacter(PushbackString input)
        {
            return input.Next();
        }  

        
        /// <summary>
        /// Utility to search a char[] for a specific char. 
        /// </summary>
        /// <param name="c">The char to search for</param>
        /// <param name="array">The char array to search in</param>
        /// <returns>True, if found, False, otherwise</returns>
        public static bool ContainsCharacter(char c, char[] array)
        {
            for (int i = 0; i < array.Length; i++)
            {
                if (c == array[i]) return true;
            } return false;
        }
    }
}
