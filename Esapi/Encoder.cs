using System;
using System.Collections;
using System.Web;
using Microsoft.Security.Application;
using Owasp.Esapi.Codecs;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{

    /// <summary> Reference implementation of the IEncoder interface. This implementation takes
    /// a whitelist approach, encoding everything not specifically identified in a
    /// list of "immune" characters.
    /// </summary>
    public class Encoder: IEncoder
    {
        static Encoder()
		{
			logger = Esapi.Logger;
		}

        /// <summary> Public constructor for encoder</summary>
        public Encoder()
        {
            AddCodec(HTML, new HtmlCodec());
            AddCodec(HTML_ATTRIBUTE, new HtmlAttributeCodec());
            AddCodec(XML, new XmlCodec());
            AddCodec(XML_ATTRIBUTE, new XmlAttributeCodec());
            AddCodec(JAVASCRIPT, new JavaScriptCodec());
            AddCodec(VBSCRIPT, new VbScriptCodec());
            AddCodec(BASE_64, new Base64Codec());
            AddCodec(URL, new UrlCodec());
        }

        private Hashtable codecs = new Hashtable();

        /// <summary>The Constant CHAR_ALPHANUMERICS. </summary>        
        public static readonly char[] CHAR_ALPHANUMERICS = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
        
        /// <summary>The Constant CHAR_UPPERS. </summary>        
        public static readonly char[] CHAR_UPPERS = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

        /// <summary>The Constant CHAR_LOWERS. </summary>
        public static readonly char[] CHAR_LOWERS = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        
        /// <summary>The Constant CHAR_DIGITS. </summary>        
        public static readonly char[] CHAR_DIGITS = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

        /// <summary> Password character set, is alphanumerics (without i, I, o, O, and 0) +
        /// selected specials like + (bad for URL encoding, | is like i and 1, etc...)
        /// </summary>                
        public static readonly char[] CHAR_PASSWORD = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '8', '9', '.', '!', '@', '$', '*', '=', '?' };
        
        /// <summary>The Constant CHAR_SPECIALS. </summary>        
        public static readonly char[] CHAR_SPECIALS = new char[] { '.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?' };

        public static readonly string BASE_64 = "Base64";

        public static readonly string HTML = "HTML";

        public static readonly string HTML_ATTRIBUTE = "HTML_ATTRIBUTE";

        public static readonly string XML = "XML";

        public static readonly string XML_ATTRIBUTE = "XML_ATTRIBUTE";

        public static readonly string URL = "URL";

        public static readonly string JAVASCRIPT = "JavaScript";

        public static readonly string VBSCRIPT = "VBScript";

        /// <summary>The logger. </summary>
        private static readonly ILogger logger;

        public string Canonicalize(ICollection codecNames, string input, bool strict)
        {
            if ( input == null ) {
                return null;
            }
            String working = input;
            ICodec codecFound = null;
            int mixedCount = 1;
            int foundCount = 0;
            bool clean = false;
            while( !clean ) {
                clean = true;
                // try each codec and keep track of which ones work             
                foreach (string codecName in codecNames) {
                    String old = working;
                    ICodec codec = (ICodec) codecs[codecNames];
                    working = codec.Decode( working );
                    if ( !old.Equals( working ) ) {
                        if ( codecFound != null && codecFound != codec ) {
                            mixedCount++;
                        }
                        codecFound = codec;
                        if ( clean ) {
                            foundCount++;
                        }
                        clean = false;
                    }
                }
            }  
            // do strict tests and handle if any mixed, multiple, nested encoding were found 
            if ( foundCount >= 2 && mixedCount > 1 ) { 
                if ( strict ) { 
                    throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input ); 
                } 
                else { 
                    logger.Warning( LogEventTypes.SECURITY, "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input ); 
                }   
            } else if ( foundCount >= 2 ) { 
                if ( strict ) { 
                    throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) encoding detected in " + input ); 
                } else { 
                    logger.Warning( LogEventTypes.SECURITY, "Multiple ("+ foundCount +"x) encoding detected in " + input ); 
                } 
             } else if ( mixedCount > 1 ) { 
                 if ( strict ) { 
                     throw new IntrusionException( "Input validation failure", "Mixed encoding ("+ mixedCount +"x) detected in " + input ); 
                } else { 
                     logger.Warning( LogEventTypes.SECURITY, "Mixed encoding ("+ mixedCount +"x) detected in " + input ); 
                } 
             } 
            return working; 
        }

        public string Normalize(string input)
        {
            return input.Normalize();
        }

        #region IEncoder Members

        public string Encode(string codecName, string input)
        {
            return GetCodec(codecName).Encode(input);
        }

        public string Decode(string codecName, string input)
        {
            return GetCodec(codecName).Decode(input);
        }

        public ICodec GetCodec(string codecName)
        {
            return (ICodec)codecs[codecName];
        }

        public void AddCodec(string codecName, ICodec codec)
        {
            codecs.Add(codecName, codec);
        }

        public void RemoveCodec(string codecName)
        {
            codecs.Remove(codecName);
        }

        #endregion
    }
}
