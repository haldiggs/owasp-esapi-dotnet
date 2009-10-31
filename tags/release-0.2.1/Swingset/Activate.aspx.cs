using System;
using System.Web.Security;

namespace Owasp.Esapi.Swingset
{
    public partial class Activate : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {            
            String userName = Request.QueryString["username"];
            String activationGuid = Request.QueryString["token"];
            MembershipUser user = Membership.GetUser(userName);
            if (user == null)
            {
                logger.Warning(LogEventTypes.SECURITY, String.Format("Non-existent user {0} unsuccessfully attempted to activate account.", userName));
            }
            else if (user.IsApproved)
            {
                logger.Warning(LogEventTypes.SECURITY, String.Format("Non-active user {0} unsuccessfully attempted to activate account.", userName));
            }
            else if (!(user.Comment == activationGuid))
            {
                logger.Warning(LogEventTypes.SECURITY, String.Format("User {0} unsuccessfully attempted to activate account (bad token).", userName));
            }
            else
            {                
                user.IsApproved = true;
                user.Comment = null;
                Membership.UpdateUser(user);                
                logger.Info(LogEventTypes.SECURITY, String.Format("User {0} successfully activated account.", userName));
                Response.Redirect("Message.aspx?message=1");
            }
            Response.Redirect("Error.aspx");
        }
    }
}
