using System.Collections.Generic;
using Owasp.Esapi.Interfaces;

namespace EsapiTest
{
    /// <summary>
    /// Custom access controller class
    /// </summary>
    /// <remarks>Need to have an explicit one because RhinoMocks
    /// cannot create named types</remarks>
    internal class ForwardAccessController : IAccessController
    {
        public IAccessController Impl { get; set; }
        #region IAccessController Members

        public bool IsAuthorized(object action, object resource)
        {
            return Impl.IsAuthorized(action, resource);
        }

        public bool IsAuthorized(object subject, object action, object resource)
        {
            return Impl.IsAuthorized(subject, action, resource);
        }

        public void AddRule(object subject, object action, object resource)
        {
            Impl.AddRule(subject, action, resource);
        }

        public void RemoveRule(object subject, object action, object resource)
        {
            Impl.RemoveRule(subject, action, resource);
        }

        #endregion
    }

    /// <summary>
    /// Forward encryptor for mocking
    /// </summary>
    internal class ForwardEncryptor : IEncryptor
    {
        public IEncryptor Impl { get; set; }
        #region IEncryptor Members

        public long TimeStamp
        {
            get { return Impl.TimeStamp; }
        }

        public string Hash(string plaintext, string salt)
        {
            return Impl.Hash(plaintext, salt);
        }

        public string Encrypt(string plaintext)
        {
            return Impl.Encrypt(plaintext);
        }

        public string Decrypt(string ciphertext)
        {
            return Impl.Decrypt(ciphertext);
        }

        public string Sign(string data)
        {
            return Impl.Sign(data);
        }

        public bool VerifySignature(string signature, string data)
        {
            return Impl.VerifySignature(signature, data);
        }

        public string Seal(string data, long timestamp)
        {
            return Impl.Seal(data, timestamp);
        }

        public string Unseal(string seal)
        {
            return Impl.Unseal(seal);
        }

        public bool VerifySeal(string seal)
        {
            return Impl.VerifySeal(seal);
        }

        #endregion
    }

    /// <summary>
    /// Forward validator
    /// </summary>
    internal class ForwardValidator : IValidator
    {
        public static IValidator DefaultValidator;
        private IValidator _instanceValidator;

        public IValidator Impl
        {
            get { return _instanceValidator == null ? DefaultValidator : _instanceValidator; }
            set { _instanceValidator = value; }
        }

        #region IValidator Members

        public bool IsValid(string rule, string input)
        {
            return Impl.IsValid(rule, input);
        }

        public void AddRule(string name, IValidationRule rule)
        {
            Impl.AddRule(name, rule);
        }

        public IValidationRule GetRule(string name)
        {
            return Impl.GetRule(name);
        }

        public void RemoveRule(string name)
        {
            Impl.RemoveRule(name);
        }

        #endregion
    }
    /// <summary>
    /// Forward validation rule
    /// </summary>
    internal class ForwardValidationRule : IValidationRule
    {
        public IValidationRule Implt { get; set; }
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            return Implt.IsValid(input);
        }

        #endregion
    }

    // Forward encoder
    internal class ForwardEncoder : IEncoder
    {
        internal static IEncoder DefaultEncoder;
        private IEncoder _instanceImpl;

        public IEncoder Impl
        {
            get { return _instanceImpl != null ? _instanceImpl : DefaultEncoder; }
            set { _instanceImpl = value; }
        }
        #region IEncoder Members

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
    internal class ForwardCodec : ICodec
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
