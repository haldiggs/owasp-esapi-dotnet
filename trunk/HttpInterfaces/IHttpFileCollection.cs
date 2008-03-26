using System;
using System.Web;

namespace HttpInterfaces
{
	public interface IHttpFileCollection
	{
		IHttpPostedFile Get(int index);
		IHttpPostedFile Get(string name);
		string GetKey(int index);

		// Properties
		string[] AllKeys { get; }
		IHttpPostedFile this[string name] { get; }
		IHttpPostedFile this[int index] { get; }
	}
}
