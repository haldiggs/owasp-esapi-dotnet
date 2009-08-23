using System.Web;
using Microsoft.Security.Application;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Codecs
{
    /// <summary>
    /// This class performs URL encoding.
    /// </summary>
    [Codec(BuiltinCodecs.Url)]
    public class UrlCodec : ICodec
    {
        #region ICodec Members

        /// <summary>
        /// URL encode the input.
        /// </summary>
        /// <param name="input">The input to encode.</param>
        /// <returns>The encoded input.</returns>
        public string Encode(string input)
        {
            return AntiXss.UrlEncode(input);  
        }

        /// <summary>
        /// URL decode the input.
        /// </summary>
        /// <param name="input">The input to decode.</param>
        /// <returns>The decoded input.</returns>
        public string Decode(string input)
        {
            return HttpUtility.UrlDecode(input); 
        }

        #endregion
    }
}
