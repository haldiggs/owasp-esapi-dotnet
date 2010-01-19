using System.Collections.ObjectModel;
using System.Collections.Generic;

namespace Owasp.Esapi
{
    /// <summary>
    /// Special charset values
    /// </summary>
    public static class CharSetValues
    {
        /// <summary>The Constant Alphanumerics. </summary>
        public static readonly char[] Alphanumerics = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
        
        /// <summary>The Constant Uppers. </summary>        
        public static readonly char[] Uppers = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
    
        /// <summary>The Constant Lowers. </summary>
        public static readonly char[] Lowers = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        
        /// <summary>The Constant CHAR_DIGITS. </summary>        
        public static readonly char[] Digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

        /// <summary> Password character set, is alphanumerics (without i, I, o, O, and 0) +
        /// selected specials like + (bad for URL encoding, | is like i and 1, etc...)
        /// </summary>                
        public static readonly char[] Password = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '8', '9', '.', '!', '@', '$', '*', '=', '?' };

        /// <summary>The Constant Specials. </summary>        
        public static readonly char[] Specials = { '.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?' };

        /// <summary>
        /// HEX characters
        /// </summary>
        public static readonly char[] Hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    }
}
