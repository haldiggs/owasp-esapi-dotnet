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
using Microsoft.Security.Application;

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
			logger = Esapi.Logger;
		}

        /// <summary> Public constructor for encoder
        /// 
        /// </summary>
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
        
        /// <summary>The Constant CHAR_LETTERS. </summary>
        internal static readonly char[] CHAR_LETTERS;

        /// <summary>The logger. </summary>
        private static readonly ILogger logger;

        public string Canonicalize(string input)
        {
            throw new NotImplementedException();
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
