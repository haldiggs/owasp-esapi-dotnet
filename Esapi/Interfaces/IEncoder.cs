
using Owasp.Esapi.Codecs;
using System.Collections;
namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IEncoder interface contains a number of methods related to encoding input
    /// so that it will be safe for a variety of interpreters. To prevent
    /// double-encoding, all encoding methods should first check to see that the
    /// input does not already contain encoded characters. There are a few methods
    /// related to decoding that are used for canonicalization purposes. See the
    /// Validator class for more information.
    ///    
    /// All of the methods here must use a "whitelist" or "positive" security model,
    /// meaning that all characters should be encoded, except for a specific list of
    /// "immune" characters that are known to be safe.    
    /// </summary>    
    public interface IEncoder
    {
        /// <summary> This method performs canonicalization on data received to ensure that it
        /// has been reduced to its most basic form before validation. For example,
        /// URL-encoded data received from ordinary "application/x-www-url-encoded"
        /// forms so that it may be validated properly.
        // </summary>
        /// <param name="input">Unvalidated input.
        /// </param>
        /// <returns> The canonicalized string.
        /// </returns>
        string Canonicalize(ICollection codecNames, string input, bool strict);

        /// <summary> Reduce all non-ascii characters to their ASCII form so that simpler
        /// validation rules can be applied. For example, an accented-e character
        /// will be changed into a regular ASCII e character.
        /// </summary>
        /// <param name="input">The value to normalize.
        /// </param>
        /// <returns>The normalized value.
        /// </returns>
        string Normalize(string input);

        string Encode(string codecName, string input);

        string Decode(string codecName, string input);

        ICodec GetCodec(string codecName);

        void AddCodec(string codecName, ICodec encoder);

        void RemoveCodec(string codecName);
    }
}
