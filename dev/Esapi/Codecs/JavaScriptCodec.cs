using System;
using Microsoft.Security.Application;

namespace Owasp.Esapi.Codecs
{
    /// <summary>
    /// This class performs JavaScript encoding. This is useful for encoding values that will be displayed in a browser
    /// as JavaScript  (i.e. &lt;script&gt; "untrusted data here" &lt;/script&gt;)
    /// </summary>
    [Codec(BuiltinCodecs.JavaScript)]
    public class JavaScriptCodec : ICodec
    {
        #region ICodec Members

        /// <summary>
        /// JavaScript encode the input.
        /// </summary>
        /// <param name="input">The input to encode.</param>
        /// <returns>The encoded input.</returns>
        public string Encode(string input)
        {
            return Microsoft.Security.Application.Encoder.JavaScriptEncode(input);
        }

        /// <summary>
        /// JavaScript decode the input.
        /// </summary>
        /// <param name="input">The input to decode.</param>
        /// <returns>The decoded input.</returns>
        /// <remarks>This method is not implemented.</remarks>
        public string Decode(string input)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}
