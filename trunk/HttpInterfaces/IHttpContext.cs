using System;
using System.Collections;
using System.Security.Principal;
using System.Web;
using System.Web.Profile;

namespace HttpInterfaces
{
	public interface IHttpContext
	{
		void AddError(Exception errorInfo);
		void ClearError();
       //  object GetConfig();
		object GetSection(string sectionName);
		void RewritePath(string path);
		void RewritePath(string path, bool rebaseClientPath);
		void RewritePath(string filePath, string pathInfo, string queryString);
		void RewritePath(string filePath, string pathInfo, string queryString, bool setClientFilePath);
		
		// Properties
		Exception[] AllErrors { get; }
		
		IHttpApplicationState Application { get; }
		IHttpApplication ApplicationInstance { get; set; }
		
		ICache Cache { get; }
		IHttpHandler CurrentHandler { get; }
	    // Not in .NET 2.0
		// RequestNotification CurrentNotification { get;}
		Exception Error { get; }
		IHttpHandler Handler { get; set; }
		bool IsCustomErrorEnabled { get; }
		bool IsDebuggingEnabled { get; }
        // Not in .NET 2.0
	    // bool IsPostNotification { get; }
		IDictionary Items { get; }
		IHttpHandler PreviousHandler { get; }
		ProfileBase Profile { get; }
		IHttpRequest Request { get; }
		IHttpResponse Response { get; }
		IHttpServerUtility Server { get; }
		IHttpSession Session { get; }
		bool SkipAuthorization { get; set; }
		DateTime Timestamp { get; }
		ITraceContext Trace { get; }
		IPrincipal User { get; set; }
	}
}
