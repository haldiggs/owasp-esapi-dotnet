using System;
using Owasp.Esapi.Runtime;
using Owasp.Esapi.Runtime.Rules;
using Owasp.Esapi.Runtime.Actions;
using System.Web.UI.WebControls;

namespace Owasp.Esapi.Swingset
{
    /// <summary>
    /// Make sure no logged-on user exceeds the max number of requests 
    /// </summary>
    [RunRule(typeof(RequestThrottleRule), new Type[] { typeof(LogAction), typeof(LogoutAction)})]
    public class Global : System.Web.HttpApplication
    {

        protected void Application_Start(object sender, EventArgs e)
        {
            
        }

        protected void Session_Start(object sender, EventArgs e)
        {

        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {

        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {

        }

        protected void Application_Error(object sender, EventArgs e)
        {
            Exception ex = Server.GetLastError();
            while (ex != null && ex.InnerException != null)
            {
                ex = ex.InnerException;
            }
            Esapi.Logger.Error(LogEventTypes.FUNCTIONALITY, "Unspecified top-level error occured", ex);
            Response.Redirect("~/Error.aspx");            
        }

        protected void Session_End(object sender, EventArgs e)
        {

        }

        protected void Application_End(object sender, EventArgs e)
        {

        }
    }
}