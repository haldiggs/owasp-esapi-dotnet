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
using System.Collections;
using System.Text;
using System.IO;
using Owasp.Esapi.Errors;
using System.Web;
using System.Globalization;

namespace Owasp.Esapi
{

    /// <summary> Reference implementation of the IEncoder interface. This implementation takes
    /// a whitelist approach, encoding everything not specifically identified in a
    /// list of "immune" characters.
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=.NET+ESAPI question">Alex Smolen</a> at<a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder">
    /// </seealso>
    public class Encoder: IEncoder
    {
        static Encoder()
		{
			logger = Esapi.Logger();
			CHAR_LETTERS = Randomizer.Union(CHAR_LOWERS, CHAR_UPPERS);
			CHAR_ALPHANUMERICS = Randomizer.Union(CHAR_LETTERS, CHAR_DIGITS);
            
            // Moved to static intializer
            InitializeMaps();
		}

        /// <summary> Public constructor for encoder
        /// 
        /// </summary>
        public Encoder()
        {
            
        }
        /// <summary>The Constant CHAR_ALPHANUMERICS. </summary>        
        public static readonly char[] CHAR_ALPHANUMERICS;

        /// <summary>The Constant CHAR_UPPERS. </summary>        
        public static readonly char[] CHAR_UPPERS = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };

        /// <summary>The Constant CHAR_LOWERS. </summary>
        public static readonly char[] CHAR_LOWERS = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };


        /// <summary>The Constant CHAR_DIGITS. </summary>        
        public static readonly char[] CHAR_DIGITS = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

        // FIXME: ENHANCE make all character sets configurable
        /// <summary> Password character set, is alphanumerics (without i, I, o, O, and 0) +
        /// selected specials like + (bad for URL encoding, | is like i and 1, etc...)
        /// </summary>                
        public static readonly char[] CHAR_PASSWORD = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '8', '9', '.', '!', '@', '$', '*', '=', '?' };


        /// <summary>The Constant CHAR_SPECIALS. </summary>        
        public static readonly char[] CHAR_SPECIALS = new char[] { '.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?' };


        /// <summary>The Constant CHAR_LETTERS. </summary>
        internal static readonly char[] CHAR_LETTERS;


        /// <summary>Encoding types </summary>
        public const int NO_ENCODING = 0;
        /// <summary>
        /// URL Encoding
        /// </summary>
        public const int URL_ENCODING = 1;

        /// <summary>
        /// Percent Encoding
        /// </summary>
        public const int PERCENT_ENCODING = 2;

        /// <summary>
        /// Entity encoding
        /// </summary>
        public const int ENTITY_ENCODING = 3;

        /// <summary>The IMMUNE HTML. </summary>        
        private static readonly char[] IMMUNE_HTML = new char[] { ',', '.', '-', '_', ' ' };

        /// <summary>The IMMUNE HTMLATTR. </summary>        
        private static readonly char[] IMMUNE_HTMLATTR = new char[] { ',', '.', '-', '_' };

        /// <summary>The IMMUNE JAVASCRIPT. </summary>        
        private static readonly char[] IMMUNE_JAVASCRIPT = new char[] { ',', '.', '-', '_', ' ' };

        /// <summary>The IMMUNE VBSCRIPT. </summary>        
        private static readonly char[] IMMUNE_VBSCRIPT = new char[] { ',', '.', '-', '_', ' ' };

        /// <summary>The IMMUNE XML. </summary>        
        private static readonly char[] IMMUNE_XML = new char[] { ',', '.', '-', '_', ' ' };

        /// <summary>The IMMUNE XMLATTR. </summary>
        private static readonly char[] IMMUNE_XMLATTR = new char[] { ',', '.', '-', '_' };

        /// <summary>The IMMUNE XPATH. </summary>
        private static readonly char[] IMMUNE_XPATH = new char[] { ',', '.', '-', '_', ' ' };

        /// <summary>The logger. </summary>
        private static readonly ILogger logger;
        
        private static Hashtable characterToEntityMap;
        
        private static Hashtable entityToCharacterMap;


        /// <summary> Simplifies percent-encoded and entity-encoded characters to their
        /// simplest form so that they can be properly validated. Attackers
        /// frequently use encoding schemes to disguise their attacks and bypass
        /// validation routines.
        /// 
        /// Handling multiple encoding schemes simultaneously is difficult, and
        /// requires some special consideration. In particular, the problem of
        /// double-encoding is difficult for parsers, and combining several encoding
        /// schemes in double-encoding makes it even harder. Consider decoding
        /// 
        /// <pre>
        /// &amp;lt;
        /// </pre>
        /// 
        /// or
        /// 
        /// <pre>
        /// %26lt;
        /// </pre>
        /// 
        /// or
        /// 
        /// <pre>
        /// &amp;lt;
        /// </pre>.
        /// 
        /// This implementation disallows ALL double-encoded characters and throws an
        /// IntrusionException when they are detected. Also, named entities that are
        /// not known are simply removed.
        /// 
        /// Note that most data from the browser is likely to be encoded with URL
        /// encoding (FIXME: RFC). The web server will decode the URL and form data
        /// once, so most encoded data received in the application must have been
        /// double-encoded by the attacker. However, some HTTP inputs are not decoded
        /// by the browser, so this routine allows a single level of decoding.
        /// 
        /// </summary>
        /// <param name="input">Unvalidated input from an HTTP request.
        /// </param>
        /// <returns> The canonicalized string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.Canonicalize(string)">
        /// </seealso>
        public string Canonicalize(string input)
        {
            StringBuilder sb = new StringBuilder();
            EncodedStringReader reader = new EncodedStringReader(input);
            while (reader.HasNext())
            {
                EncodedCharacter c = reader.NextCharacter;
                if (c != null)
                {
                    sb.Append(c.Unencoded);
                }
            }
            return sb.ToString();
        }


        /// <summary> Normalizes special characters down to ASCII using the Normalizer built
        /// into .NET        
        /// </summary>
        /// <param name="input">The value to normalize.
        /// </param>
        /// <returns>The normalized value.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.Normalize(string)">
        /// </seealso>
        public virtual string Normalize(string input)
        {
            // Split any special characters into two parts, the base character and
            // the modifier
            
            String separated = input.Normalize(NormalizationForm.FormD);
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < separated.Length; i++)
            {
                char c = separated[i];
                // remove any character that is not ASCII or is an accent
                if ((CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark) &&
                  ((int) c <= 127))
                {

                    stringBuilder.Append(c);
                }
            }

            return stringBuilder.ToString();                        
        }

        /// <summary> Checks if the character is contained in the provided array of characters.
        /// </summary>
        /// <param name="array">The array.
        /// </param>
        /// <param name="element">The element to check.
        /// </param>
        /// <returns> true, if is contained.
        /// </returns>
        private bool IsContained(char[] array, char element)
        {
            for (int i = 0; i < array.Length; i++)
            {
                if (element == array[i])
                    return true;
            }
            return false;

            // FIXME: ENHANCE Performance enhancement here but character arrays must
            // be sorted, which they're currently not.
            // return( Arrays.BinarySearch(array, element) >= 0 );
        }

        /// <summary> HTML Entity encode utility method. To avoid double-encoding, this method
        /// logs a warning if HTML entity encoded characters are passed in as input.
        /// Double-encoded characters in the input cause an exception to be thrown.        
        /// </summary>
        /// <param name="input">The input to encode.
        /// </param>
        /// <param name="immune">The immune characters.
        /// </param>
        /// <param name="baseChars">The base characters.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        private string EntityEncode(string input, char[] baseChars, char[] immune)
        {
            StringBuilder sb = new StringBuilder();
            EncodedStringReader reader = new EncodedStringReader(input);
            while (reader.HasNext())
            {
                EncodedCharacter c = reader.NextCharacter;
                if (c != null)
                {
                    if (IsContained(baseChars, c.Unencoded) || IsContained(immune, c.Unencoded))
                    {
                        sb.Append(c.Unencoded);
                    }
                    else
                    {
                        sb.Append(c.GetEncoded(ENTITY_ENCODING));
                    }
                }
            }
            return sb.ToString();
        }

        /// <summary> Encode data for use in HTML content. This method first canonicalizes and
        /// detects any double-encoding. If this check passes, then the data is
        /// entity-encoded using a whitelist.        
        /// </summary>
        /// <param name="input">The value to encode.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForHtml(string)">
        /// </seealso>
        public string EncodeForHtml(string input)
        {
            // FIXME: ENHANCE - should this just strip out nonprintables? Why send
            // &#07; to the browser?
            // FIXME: Enhance - Add a configuration for masking **** out SSN and credit
            // card

            string encoded = EntityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_HTML);
            encoded = encoded.Replace("\r", "<BR>");
            encoded = encoded.Replace("\n", "<BR>");
            return encoded;
        }

        /// <summary> Encode data for use in HTML attributes. This method first canonicalizes
        /// and detects any double-encoding. If this check passes, then the data is
        /// entity-encoded using a whitelist.        
        /// </summary>
        /// <param name="input">The value to encode.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForHtmlAttribute(string)">
        /// </seealso>
        public string EncodeForHtmlAttribute(string input)
        {
            return EntityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_HTMLATTR);
        }

        /// <summary> Encode for javascript. This method first canonicalizes and detects any
        /// double-encoding. If this check passes, then the data is encoded using a
        /// whitelist.
        /// 
        /// </summary>
        /// <param name="input">The value to encode.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForJavascript(string)">
        /// </seealso>
        public string EncodeForJavascript(string input)
        {
            return EntityEncode(input, Encoder.CHAR_ALPHANUMERICS, Encoder.IMMUNE_JAVASCRIPT);
        }

        /// <summary> Encode data for use in visual basic script. This method first
        /// canonicalizes and detects any double-encoding. If this check passes, then
        /// the data is encoded using a whitelist.
        /// 
        /// </summary>
        /// <param name="input">The value to encode.
        /// </param>
        /// <returns>The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForVbScript(string)">
        /// </seealso>
        public string EncodeForVbScript(string input)
        {
            return EntityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_VBSCRIPT);
        }

        /// <summary> This method is not recommended. The use of SqlCommand with 
        /// placeholder and parameters. is the normal
        /// and preferred approach. However, if for some reason this is impossible,
        /// then this method is provided as a weaker alternative. The best approach
        /// is to make sure any single-quotes are double-quoted. 
        /// However, this syntax does not work with all drivers, and requires
        /// modification of all queries.
        /// </summary>
        /// <param name="input">The value to encode.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForSql(string)">
        /// </seealso>
        public string EncodeForSql(string input)
        {
            string canonical = Canonicalize(input);
            return canonical.Replace("'", "''");
        }

        /// <summary> Encode data for use in LDAP queries. This method first canonicalizes and
        /// detects any double-encoding. If this check passes, then the data is
        /// encoded using a whitelist.
        /// 
        /// </summary>
        /// <param name="input"> The value to encode.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForLdap(string)">
        /// </seealso>
        public string EncodeForLdap(string input)
        {
            string canonical = Canonicalize(input);

            // FIXME: ENHANCE this is a negative list -- make positive?
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < canonical.Length; i++)
            {
                char c = canonical[i];
                switch (c)
                {

                    case '\\':
                        sb.Append("\\5c");
                        break;

                    case '*':
                        sb.Append("\\2a");
                        break;

                    case '(':
                        sb.Append("\\28");
                        break;

                    case ')':
                        sb.Append("\\29");
                        break;

                    case '\u0000':
                        sb.Append("\\00");
                        break;

                    default:
                        sb.Append(c);
                        break;

                }
            }
            return sb.ToString();
        }

        /// <summary> Encode data for use in an LDAP distinguished name. This method first
        /// canonicalizes and detects any double-encoding. If this check passes, then
        /// the data is encoded using a whitelist.
        /// 
        /// </summary>
        /// <param name="input"> The value to encode.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForDn(string)">
        /// </seealso>
        public string EncodeForDn(string input)
        {
            string canonical = Canonicalize(input);

            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            if ((canonical.Length > 0) && ((canonical[0] == ' ') || (canonical[0] == '#')))
            {
                sb.Append('\\'); // add the leading backslash if needed
            }
            for (int i = 0; i < canonical.Length; i++)
            {
                char c = canonical[i];
                switch (c)
                {

                    case '\\':
                        sb.Append("\\\\");
                        break;

                    case ',':
                        sb.Append("\\,");
                        break;

                    case '+':
                        sb.Append("\\+");
                        break;

                    case '"':
                        sb.Append("\\\"");
                        break;

                    case '<':
                        sb.Append("\\<");
                        break;

                    case '>':
                        sb.Append("\\>");
                        break;

                    case ';':
                        sb.Append("\\;");
                        break;

                    default:
                        sb.Append(c);
                        break;

                }
            }
            // add the trailing backslash if needed
            if ((canonical.Length > 1) && (canonical[input.Length - 1] == ' '))
            {
                sb.Insert(sb.Length - 1, '\\');
            }
            return sb.ToString();
        }

        /// <summary> This implementation encodes almost everything and may overencode. The
        /// difficulty is that XPath has no built in mechanism for escaping
        /// characters. It is possible to use XQuery in a parameterized way to
        /// prevent injection. For more information, refer to <a
        /// href="http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html">this
        /// article</a> which specifies the following list of characters as the most
        /// dangerous: ^&amp;&quot;*'[](). <a
        /// href="http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf">This
        /// paper</a> suggests disallowing ' and " in queries.
        /// 
        /// </summary>
        /// <param name="input"> The value to encode.
        /// </param>
        /// <returns> The encoded string.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForXPath(string)">
        /// </seealso>
        public string EncodeForXPath(string input)
        {
            return EntityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XPATH);
        }

        /// <summary> Encode data for use in an XML element. This method first canonicalizes
        /// and detects any double-encoding. If this check passes, then the data is
        /// encoded using a whitelist. The implementation should follow the <a
        /// href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
        /// Standard</a> from the W3C.
        /// [p]
        /// The use of a real XML parser is strongly encouraged. However, in the
        /// hopefully rare case that you need to make sure that data is safe for
        /// inclusion in an XML document and cannot use a parse, this method provides
        /// a safe mechanism to do so.
        /// 
        /// </summary>
        /// <param name="input"> The value to encode.
        /// </param>
        /// <returns> The encoded value.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForXml(string)">
        /// </seealso>
        public string EncodeForXml(string input)
        {
            return EntityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XML);
        }

        /// <summary> Encode data for use in an XML attribute. The implementation should follow
        /// the <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
        /// Standard</a> from the W3C. This method first canonicalizes and detects
        /// any double-encoding. If this check passes, then the data is encoded using
        /// a whitelist.
        /// [p]
        /// The use of a real XML parser is highly encouraged. However, in the
        /// hopefully rare case that you need to make sure that data is safe for
        /// inclusion in an XML document and cannot use a parse, this method provides
        /// a safe mechanism to do so.
        /// 
        /// </summary>
        /// <param name="input"> The value to encode.
        /// </param>
        /// <returns> The encoded value.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForXmlAttribute(string)">
        /// </seealso>
        public string EncodeForXmlAttribute(string input)
        {
            return EntityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XMLATTR);
        }

        /// <summary> Encode for use in a URL. This method performs <a
        /// href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding"</a>
        /// on the entire string. This method first canonicalizes and detects any
        /// double-encoding. If this check passes, then the data is encoded using a
        /// whitelist.
        /// 
        /// </summary>
        /// <param name="input"> The value to encode.
        /// </param>
        /// <returns> The encoded value.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForUrl(string)">
        /// </seealso>
        public string EncodeForUrl(string input)
        {
            string canonical = Canonicalize(input);

            try
            {
                return HttpUtility.UrlEncode(canonical);
                // TODO - Figure out what to do with this parameter - Esapi.SecurityConfiguration().CharacterEncoding
            }
            catch (IOException ex)
            {
                throw new EncodingException("Encoding failure", "Encoding not supported", ex);
            }
            catch (Exception e)
            {
                throw new EncodingException("Encoding failure", "Problem URL decoding input", e);
            }
        }

        /// <summary> Decode from URL. This method first canonicalizes and detects any
        /// double-encoding. If this check passes, then the data is decoded using URL
        /// decoding.
        /// 
        /// </summary>
        /// <param name="input"> The value to decode.
        /// </param>
        /// <returns> The decoded value.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.DecodeFromUrl(string)">
        /// </seealso>
        public String DecodeFromUrl(string input)
        {
            string canonical = Canonicalize(input);
            try
            {
                return System.Web.HttpUtility.UrlDecode(canonical);
                //TODO - Figure out what to do with this parameter, ESAPI.securityConfiguration().CharacterEncoding);
            }
            catch (IOException ex)
            {
                throw new EncodingException("Decoding failed", "Encoding not supported", ex);
            }
            catch (Exception e)
            {
                throw new EncodingException("Decoding failed", "Problem URL decoding input", e);
            }
        }

        /// <summary> Encode for base64.
        /// [p]
        /// Beware double-encoding, as this will corrupt the results and could
        /// possibly cause a downstream security mechansim to make a mistake.
        /// 
        /// </summary>
        /// <param name="input">The input to encode.
        /// </param>
        /// <param name="wrap"> If true, remove end of line characters.
        /// </param>
        /// <returns> The encoded string.
        /// </returns> 
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.EncodeForBase64(byte[], bool)">
        /// </seealso>
        public string EncodeForBase64(byte[] input, bool wrap)
        {            
            string b64 = Convert.ToBase64String(input);            
            if (!wrap)
            {
                b64 = b64.Replace("\r", "").Replace("\n", "");
            }
            return b64;
        }

        /// <summary> Decode data encoded with BASE-64 encoding.
        /// [p]
        /// Beware double-encoded data, as the results of this method could still
        /// contain encoded characters as part of attacks.
        /// 
        /// </summary>
        /// <param name="input">The data to decode.
        /// </param>
        /// <returns> The decoded byte array.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder.DecodeFromBase64(string)">
        /// </seealso>
        public byte[] DecodeFromBase64(string input)
        {            
            return Convert.FromBase64String(input);
        }

        // FIXME: ENHANCE - change formatting here to more like -- "quot", "34", //
        // quotation mark
        private static void InitializeMaps()
        {
            string[] entityNames = new string[]{"quot", "amp", "lt", "gt", "nbsp", "iexcl", "cent", "pound", "curren", "yen", "brvbar", "sect", "uml", "copy", "ordf", "laquo", "not", "shy", "reg", "macr", "deg", "plusmn", "sup2", "sup3", "acute", "micro", "para", "middot", "cedil", "sup1", "ordm", "raquo", "frac14", "frac12", "frac34", "iquest", "Agrave", "Aacute", "Acirc", "Atilde", "Auml", "Aring", "AElig", "Ccedil", "Egrave", "Eacute", "Ecirc", "Euml", "Igrave", "Iacute", "Icirc", "Iuml", "ETH", "Ntilde", "Ograve", "Oacute", "Ocirc", "Otilde", "Ouml", "times", "Oslash", "Ugrave", "Uacute", "Ucirc", "Uuml", "Yacute", "THORN", "szlig", "agrave", "aacute", "acirc", "atilde", "auml", "aring", "aelig", "ccedil", "egrave", "eacute", "ecirc", "euml", "igrave", "iacute", "icirc", "iuml", "eth", "ntilde", "ograve", "oacute", "ocirc", "otilde", "ouml", "divide", "oslash", "ugrave", "uacute", "ucirc", "uuml", "yacute", "thorn", "yuml", "OElig", "oelig", "Scaron", "scaron", "Yuml", "fnof", "circ", "tilde", "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota", "Kappa", "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi", "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega", "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "sigmaf", "sigma", "tau", "upsilon", "phi", "chi", "psi", "omega", "thetasym", "upsih", "piv", "ensp", "emsp", "thinsp", "zwnj", "zwj", "lrm", "rlm", "ndash", "mdash", "lsquo", "rsquo", "sbquo", "ldquo", "rdquo", "bdquo", "dagger", "Dagger", "bull", "hellip", "permil", "prime", "Prime", "lsaquo", "rsaquo", "oline", "frasl", "euro", "image", "weierp", "real", "trade", "alefsym", "larr", "uarr", "rarr", "darr", "harr", "crarr", "lArr", "uArr", "rArr", "dArr", "hArr", "forall", "part", "exist", "empty", "nabla", "isin", "notin", "ni", "prod", "sum", "minus", "lowast", "radic", "prop", "infin", "ang", "and", "or", "cap", "cup", "int", "there4", "sim", "cong", "asymp", "ne", 
				"equiv", "le", "ge", "sub", "sup", "nsub", "sube", "supe", "oplus", "otimes", "perp", "sdot", "lceil", "rceil", "lfloor", "rfloor", "lang", "rang", "loz", "spades", "clubs", "hearts", "diams"};

            char[] entityValues = new char[]{(char) (34), (char) (38), (char) (60), (char) (62), (char) (160), (char) (161), (char) (162), (char) (163), (char) (164), (char) (165), (char) (166), (char) (167), (char) (168), (char) (169), (char) (170), (char) (171), (char) (172), (char) (173), (char) (174), (char) (175), (char) (176), (char) (177), (char) (178), (char) (179), (char) (180), (char) (181), (char) (182), (char) (183), (char) (184), (char) (185), (char) (186), (char) (187), (char) (188), (char) (189), (char) (190), (char) (191), (char) (192), (char) (193), (char) (194), (char) (195), (char) (196), (char) (197), (char) (198), (char) (199), (char) (200), (char) (201), (char) (202), (char) (203), (char) (204), (char) (205), (char) (206), (char) (207), (char) (208), (char) (209), (char) (210), (char) (211), (char) (212), (char) (213), (char) (214), (char) (215), (char) (216), (char) (217), (char) (218), (char) (219), (char) (220), (char) (221), (char) (222), (char) (223), (char) (224), (char) (225), (char) (226), (char) (227), (char) (228), (char) (229), (char) (230), (char) (231), (char) (232), (char) (233), (char) (234), (char) (235), (char) (236), (char) (237), (char) (238), (char) (239), (char) (240), (char) (241), (char) (242), (char) (243), (char) (244), (char) (245), (char) (246), (char) (247), (char) (248), (char) (249), (char) (250), (char) (251), (char) (252), (char) (253), (char) (254), (char) (255), (char) (338), (char) (339), (char) (352), (char) (353), (char) (376), (char) (402), (char) (710), (char) (732), (char) (913), (char) (914), (char) (915), (char) (916), (char) (917), (char) (918), (char) (919), (char) (920), (char) (921), (char) (922), (char) (923), (char) (924), (char) (925), (char) (926), (char) (927), (char) (928), (char) (929), (char) (931), (char) (932), (char) (933), (char) (934), (char) (935), (char) (936), (char) (937), (char) (945), (char) (946), (char) (947), (char) (948), (char) (949), (char) (950), (char) (951), (char) (952), (char) (953), (char) (954), (char) (955), 
				(char) (956), (char) (957), (char) (958), (char) (959), (char) (960), (char) (961), (char) (962), (char) (963), (char) (964), (char) (965), (char) (966), (char) (967), (char) (968), (char) (969), (char) (977), (char) (978), (char) (982), (char) (8194), (char) (8195), (char) (8201), (char) (8204), (char) (8205), (char) (8206), (char) (8207), (char) (8211), (char) (8212), (char) (8216), (char) (8217), (char) (8218), (char) (8220), (char) (8221), (char) (8222), (char) (8224), (char) (8225), (char) (8226), (char) (8230), (char) (8240), (char) (8242), (char) (8243), (char) (8249), (char) (8250), (char) (8254), (char) (8260), (char) (8364), (char) (8465), (char) (8472), (char) (8476), (char) (8482), (char) (8501), (char) (8592), (char) (8593), (char) (8594), (char) (8595), (char) (8596), (char) (8629), (char) (8656), (char) (8657), (char) (8658), (char) (8659), (char) (8660), (char) (8704), (char) (8706), (char) (8707), (char) (8709), (char) (8711), (char) (8712), (char) (8713), (char) (8715), (char) (8719), (char) (8721), (char) (8722), (char) (8727), (char) (8730), (char) (8733), (char) (8734), (char) (8736), (char) (8743), (char) (8744), (char) (8745), (char) (8746), (char) (8747), (char) (8756), (char) (8764), (char) (8773), (char) (8776), (char) (8800), (char) (8801), (char) (8804), (char) (8805), (char) (8834), (char) (8835), (char) (8836), (char) (8838), (char) (8839), (char) (8853), (char) (8855), (char) (8869), (char) (8901), (char) (8968), (char) (8969), (char) (8970), (char) (8971), (char) (9001), (char) (9002), (char) (9674), (char) (9824), (char) (9827), (char) (9829), (char) (9830)};            
            characterToEntityMap = new Hashtable(entityNames.Length);           
            entityToCharacterMap = new Hashtable(entityValues.Length);
            for (int i = 0; i < entityNames.Length; i++)
            {
                string e = entityNames[i];
                System.Char c = entityValues[i];
                entityToCharacterMap[e] = c;
                characterToEntityMap[c] = e;
            }
        }

        /// <summary>
        ///  The main method for encoding data from the command line.
        /// </summary>
        /// <param name="args">The main method arguments (standard).</param>
        [STAThread]
        public static void Main(string[] args)
        {
            Encoder encoder = new Encoder();
            // try { System.out.println( ">>" + encoder.encodeForHTML("test <>
            // test") ); } catch( Exception e1 ) { System.out.println(" !" +
            // e1.getMessage() ); }
            // try { System.out.println( ">>" + encoder.encodeForHTML("test %41 %42
            // test") ); } catch( Exception e2 ) { System.out.println(" !" +
            // e2.getMessage() ); }
            // try { System.out.println( ">>" + encoder.encodeForHTML("test %26%42
            // test") ); } catch( Exception e2 ) { System.out.println(" !" +
            // e2.getMessage() ); }
            // try { System.out.println( ">>" + encoder.encodeForHTML("test %26amp;
            // test") ); } catch( Exception e3 ) { System.out.println(" !" +
            // e3.getMessage() ); }
            // try { System.out.println( ">>" + encoder.encodeForHTML("test &#38;
            // test") ); } catch( Exception e4 ) { System.out.println(" !" +
            // e4.getMessage() ); }
            // try { System.out.println( ">>" + encoder.encodeForHTML("test
            // &#38;amp; test") ); } catch( Exception e5 ) { System.out.println(" !"
            // + e5.getMessage() ); }
            // try { System.out.println( ">>" + encoder.encodeForHTML("test &#ridi;
            // test") ); } catch( Exception e6 ) { e6.printStackTrace() ; }
            //try {
            //	System.out.println(">>" + encoder.encodeForHTML("test &#01;&#02;&#03;&#04; test"));
            //} catch (Exception e7) {
            //	System.out.println("   !" + e7.getMessage());
            //}
        }

        private class EncodedStringReader
        {
            /// <summary>
            /// The next character in the string.
            /// </summary>            
            public EncodedCharacter NextCharacter
            {
                get
                {
                    // get the current character and move past it
                    testCharacter = nextCharacter;
                    EncodedCharacter c = null;
                    c = PeekNextCharacter(input[nextCharacter]);
                    // System.out.println( nextCharacter + ":" + (int)c.getUnencoded() +
                    // " -> " + testCharacter );
                    nextCharacter = testCharacter;
                    if (c == null)
                        return null;

                    // if the current character is encoded, check for double-encoded
                    // characters
                    if (c.IsEncoded())
                    {
                        testCharacter--;
                        EncodedCharacter next = PeekNextCharacter(c.Unencoded);
                        if (next != null)
                        {
                            if (next.IsEncoded())
                            {
                                throw new IntrusionException("Validation error", "Input contains double encoded characters.");
                            }
                            else
                            {
                                // System.out.println("Not double-encoded");
                            }
                        }
                    }
                    return c;
                }

            }
            internal string input = null;
            internal int nextCharacter = 0;
            internal int testCharacter = 0;

            /// <summary>
            /// Constructor for EncodedStringReader
            /// </summary>
            /// <param name="input">The string to read.</param>
            public EncodedStringReader(string input)
            {
                // System.out.println( "***" + input );
                if (input == null)
                {
                    this.input = "";
                }
                else
                {
                    this.input = input;
                }
            }

            /// <summary>
            /// Checks if there is another character.
            /// </summary>
            /// <returns>true, if another character exists.</returns>
            public virtual bool HasNext()
            {
                return nextCharacter < input.Length;
            }

            private EncodedCharacter PeekNextCharacter(char currentCharacter)
            {
                // if we're on the last character
                if (testCharacter == input.Length - 1)
                {
                    testCharacter++;
                    return new EncodedCharacter(currentCharacter);
                }
                else if (currentCharacter == '&')
                {
                    // if parsing an entity returns null - then we should skip it by
                    // returning null here
                    EncodedCharacter encoded = ParseEntity(input, testCharacter);
                    return encoded;
                }
                else if (currentCharacter == '%')
                {
                    // if parsing a % encoded character returns null, then just
                    // return the % and keep going
                    EncodedCharacter encoded = ParsePercent(input, testCharacter);
                    if (encoded != null)
                    {
                        return encoded;
                    }
                    // FIXME: AAA add UTF-7 decoding
                    // FIXME: others?
                }
                testCharacter++;
                return new EncodedCharacter(currentCharacter);
            }

            /// <summary>
            /// Parases a percentage value.
            /// </summary>
            /// <param name="s">The string to parse.</param>
            /// <param name="startIndex">The index to begin parsing at.</param>
            /// <returns>The character represented.</returns>
            public virtual EncodedCharacter ParsePercent(string s, int startIndex)
            {
                // FIXME: AAA check if these can be longer than 2 characters?
                // consume as many as possible?
                string possible = s.Substring(startIndex + 1, (startIndex + 3) - (startIndex + 1));
                try
                {                    
                    int c = System.Convert.ToInt32(possible, 16);
                    testCharacter += 3;
                    return new EncodedCharacter("%" + possible, (char)c, Encoder.PERCENT_ENCODING);
                }
                catch (System.FormatException e)
                {
                    // System.out.println("Found % but there was no encoded character following it");
                    return null;
                }
            }

            /// <summary>
            /// Return a character or null if no good character can be parsed. Badly
            /// formed characters that simply can't be parsed are dropped, such as
            /// &amp;ridi; for which there is no reasonable translation. Characters that
            /// aren't terminated by a semicolon are also dropped. Note that this is
            /// legal html
            /// 
            /// <pre>
            /// &lt;body onload=&quot;&amp;#x61ler&amp;#116('xss body')&quot;&gt;
            /// </pre>
            /// </summary>
            /// <param name="s">The string to parse from.</param>
            /// <param name="startIndex">The index to begin parsing at.</param>
            /// <returns>The parsed entity.</returns>
            public virtual EncodedCharacter ParseEntity(string s, int startIndex)
            {
                // FIXME: AAA - figure out how to handle non-semicolon terminated
                // characters                
                int semiIndex = input.IndexOf(";", startIndex + 1);
                if (semiIndex != -1)
                {
                    if (semiIndex - startIndex <= 8)
                    {
                        string possible = input.Substring(startIndex + 1, (semiIndex) - (startIndex + 1)).ToLower();
                        // System.out.println( " " + possible + " -> " +
                        // testCharacter );

                        

                        if (Encoder.entityToCharacterMap[possible] != null)
                        {
                            char entity = (char)Encoder.entityToCharacterMap[possible];
                            testCharacter += possible.Length + 2;
                            return new EncodedCharacter("&" + possible + ";", entity, Encoder.ENTITY_ENCODING);
                        }
                        else if (possible[0] == '#')
                        {
                            // advance past this either way
                            testCharacter += possible.Length + 2;
                            try
                            {
                                // FIXME: Enhance - consider supporting #x encoding
                                int c = System.Int32.Parse(possible.Substring(1));
                                return new EncodedCharacter("&#" + (char)c + ";", (char)c, Encoder.ENTITY_ENCODING);
                            }
                            catch (System.FormatException e)
                            {
                                // invalid character - return null
                                Encoder.logger.Warning(LogEventTypes.SECURITY, "Invalid numeric entity encoding &" + possible + ";");
                            }
                        }
                    }
                }
                // System.out.println("Found & but there was no entity following it");
                testCharacter++;
                return new EncodedCharacter("&", '&', NO_ENCODING);
            }
        }

        /// <summary>
        ///  A class for representing an encoded character.
        /// </summary>
        public class EncodedCharacter
        {
            /// <summary>
            ///  An unencoded char.
            /// </summary>
            public char Unencoded
            {
                get
                {
                    return character;
                }

            }
            internal string raw = ""; // the core of the encoded representation (without
            // the prefix or suffix)
            internal char character = (char)(0);
            internal int originalEncoding;

            /// <summary>
            ///  EncodedCharacter contsructor.
            /// </summary>
            /// <param name="character">Character to represent.</param>
            public EncodedCharacter(char character)
            {;
                this.raw = "" + character;
                this.character = character;
            }

            /// <summary>
            ///  Checks if value is encoded.
            /// </summary>
            /// <returns></returns>
            public virtual bool IsEncoded()
            {
                return (raw.Length != 1);
            }

            /// <summary>
            /// Constructor for EncodedCharacter.
            /// </summary>
            /// <param name="raw">The raw string.</param>
            /// <param name="character">The character to represent.</param>
            /// <param name="originalEncoding">An int value represent the original encoding.</param>
            public EncodedCharacter(string raw, char character, int originalEncoding)
            {
                this.raw = raw;
                this.character = character;
                this.originalEncoding = originalEncoding;
            }

            /// <summary>
            /// Gets an encoding from an int value.
            /// </summary>
            /// <param name="encoding">The int value.</param>
            /// <returns>The encoding.</returns>
            public virtual string GetEncoded(int encoding)
            {
                switch (encoding)
                {

                    case Encoder.NO_ENCODING:
                        return "" + character;

                    case Encoder.URL_ENCODING:
                        // FIXME: look up rules
                        if (System.Char.IsWhiteSpace(character))
                            return "+";
                        if (System.Char.IsLetterOrDigit(character))
                            return "" + character;
                        return "%" + (int)character;

                    case Encoder.PERCENT_ENCODING:
                        return "%" + (int)character;

                    case Encoder.ENTITY_ENCODING:                        
                        string entityName = (string) Encoder.characterToEntityMap[character];
                        if (entityName != null)
                            return "&" + entityName + ";";
                        return "&#" + (int)character + ";";

                    default:
                        return null;

                }
            }
        }

    }
}
