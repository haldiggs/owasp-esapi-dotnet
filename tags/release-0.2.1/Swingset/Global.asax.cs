using System;

namespace Owasp.Esapi.Swingset
{
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