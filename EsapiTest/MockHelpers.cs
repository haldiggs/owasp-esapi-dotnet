using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Web;
using System.Web.Hosting;
using System.Web.SessionState;
using System.Runtime.Remoting.Messaging;

namespace EsapiTest
{
    /// <remarks>
    /// From http://www.jasonbock.net/JB/Default.aspx?blog=entry.161daabc728842aca6f329d87c81cfcb
    /// </remarks>
    public sealed class MockHttpContext
    {
        private const string ThreadDataKeyAppPath = ".appPath";
        private const string ThreadDataKeyAppPathValue = "c:\\inetpub\\wwwroot\\webapp\\";
        private const string ThreadDataKeyAppVPath = ".appVPath";
        private const string ThreadDataKeyAppVPathValue = "/webapp";
        
        private HttpContext _context = null;

        public MockHttpContext()
            : this("default.aspx", string.Empty)
        {
        }

        public MockHttpContext(string page, string query)
        {
            Thread.GetDomain().SetData( ThreadDataKeyAppPath, ThreadDataKeyAppPathValue);
            Thread.GetDomain().SetData( ThreadDataKeyAppVPath, ThreadDataKeyAppVPathValue);

            SimpleWorkerRequest request = new SimpleWorkerRequest(page, query, new StringWriter());
            _context = new HttpContext(request);

            HttpSessionStateContainer container = new HttpSessionStateContainer( Guid.NewGuid().ToString("N"), new SessionStateItemCollection(), 
                                                        new HttpStaticObjectsCollection(), 5, true, HttpCookieMode.AutoDetect, SessionStateMode.InProc, 
                                                        false);

            HttpSessionState state = Activator.CreateInstance( typeof(HttpSessionState), 
                                        BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.CreateInstance,
                                        null, new object[] { container }, CultureInfo.CurrentCulture) as HttpSessionState;
            _context.Items["AspSession"] = state;
        }

        public HttpContext Context
        {
            get
            {
                return _context;
            }
        }

        /// <summary>
        /// Set a mock context as HttpContext.Current
        /// </summary>
        public static void InitializeCurrentContext()
        {
            CallContext.HostContext = (new MockHttpContext()).Context;
        }

        /// <summary>
        /// Set current http context
        /// </summary>
        /// <param name="context"></param>
        public static void SetCurrentContext(MockHttpContext context)
        {
            if (context == null) {
                throw new ArgumentNullException("request");
            }
            CallContext.HostContext = context.Context;
        }
    }
}
