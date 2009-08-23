using System;
using Microsoft.Security.Application;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Codecs
{
    /// <summary>
    /// This class performs VBScript encoding. This is useful for encoding values that will be displayed in a browser
    /// as JavaScript  (i.e. &lt;script type="VbScript" &gt; "untrusted data here" &lt;/script&gt;)
    /// </summary>
    [Codec(BuiltinCodecs.VbScript)]
    public class VbScriptCodec : ICodec
    {
        #region ICodec Members

        /// <summary>
        /// VBScript encode the input.
        /// </summary>
        /// <param name="input">The input to encode.</param>
        /// <returns>The encoded input.</returns>
        public string Encode(string input)
        {
            return AntiXss.VisualBasicScriptEncode(input);
        }

        /// <summary>
        /// VbScript decode the input.
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
