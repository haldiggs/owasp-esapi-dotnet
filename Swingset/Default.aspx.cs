using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace Owasp.Esapi.Swingset
{
    public partial class _Default : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (User.IsInRole("user"))
            {
                Response.Redirect("Users/Default.aspx");
            }
        }

        protected void EsapiLoginStatus_LoggingOut(object sender, LoginCancelEventArgs e)
        {
            logger.Info(LogEventTypes.SECURITY, "User logging out.");
        }
    }
}
