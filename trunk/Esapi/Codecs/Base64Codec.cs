using System;
using Owasp.Esapi.Interfaces;
using System.Text;

namespace Owasp.Esapi.Codecs
{
    class Base64Codec:ICodec
    {
        #region ICodec Members

        public string Encode(string input)
        {
            byte[] inputBytes = Encoding.GetEncoding(Esapi.SecurityConfiguration.CharacterEncoding).GetBytes(input);
            return Convert.ToBase64String(inputBytes);
        }

        public string Decode(string input)
        {
            byte[] inputBytes = Convert.FromBase64String(input);
            return Encoding.GetEncoding(Esapi.SecurityConfiguration.CharacterEncoding).GetString(inputBytes);
        }

        #endregion
    }
}
