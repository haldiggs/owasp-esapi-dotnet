using System.Collections.Generic;
using Owasp.Esapi.Interfaces;

namespace EsapiTest.Surrogates
{
    // Forward encoder
    internal class SurrogateEncoder : IEncoder
    {
        internal static IEncoder DefaultEncoder;
        private IEncoder _instanceImpl;

        public IEncoder Impl
        {
            get { return _instanceImpl != null ? _instanceImpl : DefaultEncoder; }
            set { _instanceImpl = value; }
        }
        #region IEncoder Members

        public string Canonicalize(string input, bool strict)
        {
            return Impl.Canonicalize(input, strict);
        }

        public string Canonicalize(IEnumerable<string> codecNames, string input, bool strict)
        {
            return Impl.Canonicalize(codecNames, input, strict);
        }

        public string Normalize(string input)
        {
            return Impl.Normalize(input);
        }

        public string Encode(string codecName, string input)
        {
            return Impl.Encode(codecName, input);
        }

        public string Decode(string codecName, string input)
        {
            return Impl.Decode(codecName, input);
        }

        public ICodec GetCodec(string codecName)
        {
            return Impl.GetCodec(codecName);
        }

        public void AddCodec(string codecName, ICodec codec)
        {
            Impl.AddCodec(codecName, codec);
        }

        public void RemoveCodec(string codecName)
        {
            Impl.RemoveCodec(codecName);
        }

        #endregion
    }
    // Forward codec
    internal class SurrogateCodec : ICodec
    {
        public ICodec Impl { get; set; }
        #region ICodec Members

        public string Encode(string input)
        {
            return Impl.Encode(input);
        }

        public string Decode(string input)
        {
            return Impl.Decode(input);
        }

        #endregion
    }
}
