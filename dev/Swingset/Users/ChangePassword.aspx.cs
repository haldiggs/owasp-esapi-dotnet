using System;

namespace Owasp.Esapi.Swingset.Users
{
    public partial class ChangePassword : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }
        
        protected void EsapiChangePassword_ChangedPassword(object sender, EventArgs e)
        {
            logger.Info(LogEventTypes.SECURITY, "User has changed their password.");            
        }

        protected void EsapiChangePassword_ChangePasswordError(object sender, EventArgs e)
        {
            logger.Warning(LogEventTypes.SECURITY, "User attempted to change their password, but failed.");
        }
    }
}
