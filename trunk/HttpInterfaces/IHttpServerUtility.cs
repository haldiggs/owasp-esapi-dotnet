using System;

namespace HttpInterfaces
{
	public interface IHttpServerUtility
	{
		string MachineName {get;}

		int ScriptTimeout {get; set;}

		object CreateObject(string progID);

		object CreateObject(Type type);

		object CreateObjectFromClsid(string clsid);

		string MapPath(string path);

		Exception GetLastError();

		void ClearError();

		void Execute(string path);

		void Execute(string path, System.IO.TextWriter writer);

		void Execute(string path, bool preserveForm);

		void Execute(string path, System.IO.TextWriter writer, bool preserveForm);

		void Execute(System.Web.IHttpHandler handler, System.IO.TextWriter writer, bool preserveForm);

		void Transfer(string path, bool preserveForm);

		void Transfer(string path);

		void Transfer(System.Web.IHttpHandler handler, bool preserveForm);

		void TransferRequest(string path);

		void TransferRequest(string path, bool preserveForm);

		void TransferRequest(string path, bool preserveForm, string method, System.Collections.Specialized.NameValueCollection headers);

		string HtmlDecode(string s);

		void HtmlDecode(string s, System.IO.TextWriter output);

		string HtmlEncode(string s);

		void HtmlEncode(string s, System.IO.TextWriter output);

		string UrlEncode(string s);

		string UrlPathEncode(string s);

		void UrlEncode(string s, System.IO.TextWriter output);

		string UrlDecode(string s);

		void UrlDecode(string s, System.IO.TextWriter output);
	}
}
