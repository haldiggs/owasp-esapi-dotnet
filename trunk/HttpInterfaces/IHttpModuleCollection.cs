using System;
using System.Web;

namespace HttpInterfaces
{
	public interface IHttpModuleCollection
	{
		IHttpModule Get(int index);
		IHttpModule Get(string name);
		string GetKey(int index);

		// Properties
		string[] AllKeys { get; }
		IHttpModule this[string name] { get; }
		IHttpModule this[int index] { get; }
	}

}
