using System;

namespace HttpInterfaces
{
	public interface IHttpClientCertificate
	{
		string Get(string field);

		// Properties
		byte[] BinaryIssuer { get; }
		int CertEncoding { get; }
		byte[] Certificate { get; }
		string Cookie { get; }
		int Flags { get; }
		bool IsPresent { get; }
		string Issuer { get; }
		bool IsValid { get; }
		int KeySize { get; }
		byte[] PublicKey { get; }
		int SecretKeySize { get; }
		string SerialNumber { get; }
		string ServerIssuer { get; }
		string ServerSubject { get; }
		string Subject { get; }
		DateTime ValidFrom { get; }
		DateTime ValidUntil { get; }
	}

}
