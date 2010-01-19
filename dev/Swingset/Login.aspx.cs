using System;
using System.Web.Security;
using System.Web.UI.WebControls;

namespace Owasp.Esapi.Swingset
{
    public partial class Login : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (User.IsInRole("user"))
            {
                Response.Redirect("Users/Default.aspx");
            }
            if (User.IsInRole("admin"))
            {
                Response.Redirect("Administrators/Default.aspx");
            }
            
            SiteMapPath smpSwingset;
            smpSwingset = (SiteMapPath) Master.FindControl("smpSwingset");
            if (smpSwingset != null)
            {
                smpSwingset.Visible = false;
            }
        }

        protected void EsapiLogin_LoggedIn(object sender, EventArgs e)
        {
            String userName = EsapiLogin.UserName;
            logger.Info(LogEventTypes.SECURITY, String.Format("User {0} has successfully logged in.", userName));
        }

        protected void EsapiLogin_LoginError(object sender, EventArgs e)
        {
            string userName = EsapiLogin.UserName;
            MembershipUser user = Membership.GetUser(userName);
            if (user == null)
            {
                logger.Warning(LogEventTypes.SECURITY, String.Format("The login attempt failed for user {0}.", userName));
            }
            else if (user.IsLockedOut)
            {
                logger.Warning(LogEventTypes.SECURITY, String.Format("The login attempt failed for user {0} because the user is locked out.", userName));
            }
            else if (!user.IsApproved)
            {
                logger.Warning(LogEventTypes.SECURITY, String.Format("The login attempt failed for user {0} because the user is not yet approved.", userName));
            }
            else
            {
                logger.Warning(LogEventTypes.SECURITY, String.Format("The login attempt failed for user {0} because they did not supply the correct password.", userName));
            }
        }

        protected void EsapiLogin_Authenticate(object sender, AuthenticateEventArgs e)
        {
            
            string userName = EsapiLogin.UserName;
            string password = EsapiLogin.Password;            
            if (Membership.GetUser(userName) != null && Membership.GetUser(userName).IsOnline)
            {
                // e.Authenticated = false;
                logger.Warning(LogEventTypes.SECURITY, String.Format("User has attempted to log in with a user account {0} that already has an active session.", userName));
            }
            e.Authenticated = Membership.ValidateUser(userName, password);
        }
    }
}
