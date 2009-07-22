using System.Web;
using Microsoft.Security.Application;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Codecs
{
    class UrlCodec:ICodec
    {
        #region ICodec Members

        public string Encode(string input)
        {
            return AntiXss.UrlEncode(input);  
        }

        public string Decode(string input)
        {
            return HttpUtility.UrlDecode(input); 
        }

        #endregion
    }
}
