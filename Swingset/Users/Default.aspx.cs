using System.Web.UI.WebControls;

namespace Owasp.Esapi.Swingset.Users
{
    public partial class Default : SwingsetPage
    {
        protected void EsapiLoginStatus_LoggingOut(object sender, LoginCancelEventArgs e)
        {
            logger.Info(LogEventTypes.SECURITY, "User logging out.");
        }
    }
}
