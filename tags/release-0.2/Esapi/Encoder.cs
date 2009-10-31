using System;
using System.Collections;
using System.Web;
using Microsoft.Security.Application;
using Owasp.Esapi.Codecs;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using System.Collections.Generic;

namespace Owasp.Esapi
{

    /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IEncoder" />
    /// <summary> Reference implementation of the <see cref="Owasp.Esapi.Interfaces.IEncoder"/> interface, based on the AntiXss library.
    /// </summary>
    public class Encoder: IEncoder
    {
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

        private Dictionary<string, ICodec> codecs = new Dictionary<string, ICodec>();

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

        /// <summary>
        /// The Base64 codec name.
        /// </summary>
        public static readonly string BASE_64 = "Base64";

        /// <summary>
        /// The HTML codec name.
        /// </summary>
        public static readonly string HTML = "HTML";

        /// <summary>
        /// The HTML attribute codec name.
        /// </summary>
        public static readonly string HTML_ATTRIBUTE = "HTML_ATTRIBUTE";

        /// <summary>
        /// The XML codec name.
        /// </summary>
        public static readonly string XML = "XML";

        /// <summary>
        /// The XML attribute codec name.
        /// </summary>
        public static readonly string XML_ATTRIBUTE = "XML_ATTRIBUTE";

        /// <summary>
        /// The URL codec name.
        /// </summary>
        public static readonly string URL = "URL";

        /// <summary>
        /// The JavaScript codec name.
        /// </summary>
        public static readonly string JAVASCRIPT = "JavaScript";

        /// <summary>
        /// The VBScript codec name.
        /// </summary>
        public static readonly string VBSCRIPT = "VBScript";

        /// <summary>The logger. </summary>
        private static readonly ILogger logger = Esapi.Logger;

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IEncoder.Canonicalize(ICollection, string, bool)" />
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
                    ICodec codec = codecs[codecName];
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

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IEncoder.Normalize(string)" />
        public string Normalize(string input)
        {
            return input.Normalize();
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IEncoder.Encode(string, string)" />
        public string Encode(string codecName, string input)
        {
            ICodec codec = GetCodec(codecName);
            if (codec == null) {
                throw new ArgumentOutOfRangeException("codecName");
            }

            return codec.Encode(input);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IEncoder.Decode(string, string)" />
        public string Decode(string codecName, string input)
        {
            ICodec codec = GetCodec(codecName);
            if (codec == null) {
                throw new ArgumentOutOfRangeException("codecName");
            }

            return codec.Decode(input);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IEncoder.GetCodec(string)" />
        public ICodec GetCodec(string codecName)
        {
            if (codecName == null) {
                throw new ArgumentNullException("codecName");
            }

            ICodec codec;
            codecs.TryGetValue(codecName, out codec);
            return codec;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IEncoder.AddCodec(string, ICodec)" />
        public void AddCodec(string codecName, ICodec codec)
        {
            if (codecName == null) {
                throw new ArgumentNullException("codecName");
            }
            codecs.Add(codecName, codec);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IEncoder.RemoveCodec(string)" />
        public void RemoveCodec(string codecName)
        {
            codecs.Remove(codecName);
        }

    }
}
