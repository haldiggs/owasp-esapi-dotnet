using System;
using Microsoft.Security.Application;

namespace Owasp.Esapi.Codecs
{
    /// <summary>
    /// This class performs XML attribute encoding.
    /// </summary>
    [Codec(BuiltinCodecs.XmlAttribute)]
    public class XmlAttributeCodec : ICodec
    {
        #region ICodec Members

        /// <summary>
        /// XML attribute encode the input.
        /// </summary>
        /// <param name="input">The input to encode.</param>
        /// <returns>The encoded input.</returns>
        public string Encode(string input)
        {
            return AntiXss.XmlAttributeEncode(input);
        }

        /// <summary>
        /// XML attribute decode the input.
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
