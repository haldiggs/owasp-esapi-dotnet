using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Codecs
{
	/// <summary>
	/// This class performs HTML attribute encoding. This is useful for encoding values that will be displayed in a browser
	/// as an HTML attribute (i.e. &lt;input text="untrusted data here"&gt;)
	/// </summary>
	[Codec(BuiltinCodecs.HtmlAttribute)]
	public class HtmlAttributeCodec : ICodec
	{
		#region ICodec Members

		/// <summary>
		/// HTML attribute encode the input.
		/// </summary>
		/// <param name="input">The input to encode.</param>
		/// <returns>The encoded input.</returns>
		public string Encode(string input)
		{
			return Microsoft.Security.Application.Encoder.HtmlAttributeEncode(input);
		}

		/// <summary>
		/// HTML attribute decode the input.
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
