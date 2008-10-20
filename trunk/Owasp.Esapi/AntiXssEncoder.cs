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
using System.Collections.Generic;
using System.Text;
using Owasp.Esapi.Interfaces;
using Microsoft.Security.Application;

namespace Owasp.Esapi
{

    /// <summary> Reference implementation of the IEncoder interface. This implementation uses the <a
    /// href="http://www.microsoft.com/downloads/details.aspx?familyid=EFB9C819-53FF-4F82-BFAF-E11625130C25">
    /// Microsoft AntiXSS Library</a> to perform some of the encoding functions. When the AntiXSS framework does not
    /// support an interface method, then the class delegates to the default Encoder interface.
    /// 
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=.NET+ESAPI question">Alex Smolen</a> at<a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> October 9, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IEncoder">
    /// </seealso>
    public class AntiXssEncoder : Encoder
    {
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
        new public string EncodeForHtml(string input)
        {
            return AntiXss.HtmlEncode(input);
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
        new public string EncodeForHtmlAttribute(string input)
        {
            return AntiXss.HtmlAttributeEncode(input);                        
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
        new public string EncodeForJavascript(string input)
        {
            return AntiXss.JavaScriptEncode(input);            
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
        new public string EncodeForVbScript(string input)
        {
            return AntiXss.VisualBasicScriptEncode(input);
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
        new public string EncodeForUrl(string input)
        {
            return AntiXss.UrlEncode(input);            
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
        new public string EncodeForXml(string input)
        {
            return AntiXss.XmlEncode(input);            
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
        new public string EncodeForXmlAttribute(string input)
        {
            return AntiXss.XmlAttributeEncode(input);
        }
        
    }
}
