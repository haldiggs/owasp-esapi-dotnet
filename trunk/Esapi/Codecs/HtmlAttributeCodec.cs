using System;
using Microsoft.Security.Application;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Codecs
{
    class HtmlAttributeCodec:ICodec
    {
        #region ICodec Members

        public string Encode(string input)
        {
            return AntiXss.HtmlAttributeEncode(input);
        }

        public string Decode(string input)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}
