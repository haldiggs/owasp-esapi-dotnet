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
            
        }

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

        /// <summary>The logger. </summary>
        private static readonly ILogger logger;

        private IList codecs = new ArrayList();

        public string Canonicalize(string input)
        {            
            return Canonicalize(input, true);
        }

        public string Canonicalize(string input, bool strict)
        {
            if ( input == null ) {
                return null;
            }
            String working = input;
            Codec codecFound = null;
            int mixedCount = 1;
            int foundCount = 0;
            bool clean = false;
            while( !clean ) {
                clean = true;
                // try each codec and keep track of which ones work             
                foreach (Codec codec in codecs) {
                    String old = working;
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

        public virtual string Normalize(string input)
        {
            throw new NotImplementedException();
        }

        public string EncodeForHtml(string input)
        {            
            return AntiXss.HtmlEncode(input);
        }

        public string EncodeForHtmlAttribute(string input)
        {
            return AntiXss.HtmlAttributeEncode(input);
        }

        public string EncodeForJavascript(string input)
        {
            return AntiXss.JavaScriptEncode(input);
        }

        public string EncodeForVbScript(string input)
        {
            return AntiXss.VisualBasicScriptEncode(input);
        }

        public string EncodeForSql(string input)
        {
            throw new NotImplementedException();
        }

        public string EncodeForLdap(string input)
        {
            throw new NotImplementedException();
        }

        public string EncodeForDn(string input)
        {
            throw new NotImplementedException();
        }

        public string EncodeForXPath(string input)
        {
            throw new NotImplementedException();
        }
       
        public string EncodeForXml(string input)
        {
            return AntiXss.XmlEncode(input);
        }

        public string EncodeForXmlAttribute(string input)
        {
            return AntiXss.XmlAttributeEncode(input);
        }

        public string EncodeForUrl(string input)
        {
            return AntiXss.UrlEncode(input);            
        }

        public String DecodeFromUrl(string input)
        {
            return HttpUtility.UrlDecode(input);                
        }

        public string EncodeForBase64(byte[] input)
        {            
            return Convert.ToBase64String(input);
        }

        public byte[] DecodeFromBase64(string input)
        {            
            return Convert.FromBase64String(input);
        }                
    }
}
