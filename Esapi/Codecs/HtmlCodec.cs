using System;
using Microsoft.Security.Application;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Codecs
{
    class HtmlCodec: ICodec
    {
        #region ICodec Members

        public string Encode(string input)
        {
            return AntiXss.HtmlEncode(input);
        }

        public string Decode(string input)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}
