using System;
using System.Web;
using System.Web.Caching;
using System.Web.SessionState;
using DeftTech.DuckTyping;

namespace HttpInterfaces
{
	public static class WebContext
	{
		public static IHttpContext Current
		{
			get
			{
				return Cast(HttpContext.Current);
			}
		}

		#region Helper methods for casting Http Intrinsics
		public static IHttpContext Cast(HttpContext context)
		{
			return DuckTyping.Cast<IHttpContext>(context);
		}

		public static IHttpRequest Cast(HttpRequest request)
		{
			return DuckTyping.Cast<IHttpRequest>(request);
		}

		public static IHttpResponse Cast(HttpResponse response)
		{
			return DuckTyping.Cast<IHttpResponse>(response);
		}

		public static IHttpSession Cast(HttpSessionState session)
		{
			return DuckTyping.Cast<IHttpSession>(session);
		}

		public static IHttpApplication Cast(HttpApplication application)
		{
			return DuckTyping.Cast<IHttpApplication>(application);
		}

		public static IHttpApplicationState Cast(HttpApplicationState application)
		{
			return DuckTyping.Cast<IHttpApplicationState>(application);
		}

		public static IHttpServerUtility Cast(HttpServerUtility server)
		{
			return DuckTyping.Cast<IHttpServerUtility>(server);
		}

		public static IHttpCachePolicy Cast(HttpCachePolicy cachePolicy)
		{
			return DuckTyping.Cast<IHttpCachePolicy>(cachePolicy);
		}

		public static IHttpClientCertificate Cast(HttpClientCertificate clientCertificate)
		{
			return DuckTyping.Cast<IHttpClientCertificate>(clientCertificate);
		}

		public static IHttpFileCollection Cast(HttpFileCollection files)
		{
			return DuckTyping.Cast<IHttpFileCollection>(files);
		}

		public static IHttpModuleCollection Cast(HttpModuleCollection modules)
		{
			return DuckTyping.Cast<IHttpModuleCollection>(modules);
		}

		public static ITraceContext Cast(TraceContext context)
		{
			return DuckTyping.Cast<ITraceContext>(context);
		}

		public static ICache Cast(Cache cache)
		{
			return DuckTyping.Cast<ICache>(cache);
		}
		#endregion
	}
}
