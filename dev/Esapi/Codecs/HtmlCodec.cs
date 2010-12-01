using System;
using System.Web;
using Microsoft.Security.Application;

namespace Owasp.Esapi.Codecs
{
    /// <summary>
    /// This class performs HTML encoding. This is useful for encoding values that will be displayed in a browser
    /// as HTML  (i.e. &lt;b&gt; "untrusted data here" &lt;/b&gt;)
    /// </summary>
    [Codec(BuiltinCodecs.Html)]
    public class HtmlCodec : ICodec
    {
        #region ICodec Members

        /// <summary>
        /// HTML encode the input.
        /// </summary>
        /// <param name="input">The input to encode.</param>
        /// <returns>The encoded input.</returns>
        public string Encode(string input)
        {

            return Microsoft.Security.Application.Encoder.HtmlEncode(input);
        }

        /// <summary>
        /// HTML decode the input.
        /// </summary>
        /// <param name="input">The input to decode.</param>
        /// <returns>The decoded input.</returns>
        /// <remarks>This method is not implemented.</remarks>
        public string Decode(string input)
        {
            return HttpUtility.HtmlDecode(input);            
        }

        #endregion
    }
}
