
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
        /// <summary>
        /// This method performs canonicalization on data received to ensure that it
        /// has been reduced to its most basic form before validation. Canonicalization is the 
        /// process of decoding something to its simplest form. The application can supply a list of
        /// codecs and the data will be decoded by each codec cosecutively, until it has reaced it's
        /// canonical form.
        ///  </summary>
        /// <param name="codecNames">
        /// The names of the codecs to use for canonicalization. These codecs will be used in order.
        /// </param>
        /// <param name="input">Unvalidated input.
        /// </param>
        /// <param name="strict">If this is true, then double encodings will cause an exception.
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

        /// <summary>
        /// This method encodes the input according to the given codec name.
        /// </summary>
        /// <param name="codecName">The codec to use to encode the input.</param>
        /// <param name="input">The input to encode.</param>
        /// <returns>The encoded input.</returns>
        string Encode(string codecName, string input);

        /// <summary>
        /// This method decodes the input according to the given codec name.
        /// </summary>
        /// <param name="codecName">The codec to use to decode the input.</param>
        /// <param name="input">The input to decode.</param>
        /// <returns>The decoded input.</returns>
        string Decode(string codecName, string input);

        /// <summary>
        /// This method returns the codec associated with the given codec name.
        /// </summary>
        /// <param name="codecName">The codec name to return.</param>
        /// <returns>The codec associated with the codec name.</returns>
        ICodec GetCodec(string codecName);

        /// <summary>
        /// This method adds the given codec with the given codec name to the Encoder.
        /// </summary>
        /// <param name="codecName">The name of the codec to add.</param>
        /// <param name="codec">The codec to add.</param>
        void AddCodec(string codecName, ICodec codec);

        /// <summary>
        /// This method removes the codec with the given codec name.
        /// </summary>
        /// <param name="codecName">The name of the codec to remove.</param>
        void RemoveCodec(string codecName);
    }
}
