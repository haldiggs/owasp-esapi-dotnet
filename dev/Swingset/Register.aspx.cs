using System;
using System.Web.Security;

namespace Owasp.Esapi.Swingset
{
    public partial class Register : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void EsapiCreateUserWizard_CreatedUser(object sender, EventArgs e)
        {
            string userName = EsapiCreateUserWizard.UserName;
            logger.Info(LogEventTypes.SECURITY, String.Format("User {0} was created.", userName));
            if (!Roles.RoleExists("user"))
            {
                Roles.CreateRole("user");
            }
            Roles.AddUserToRole(userName, "user");
            logger.Info(LogEventTypes.SECURITY, String.Format("User {0} added to 'user' role.", userName));
            MembershipUser user = Membership.GetUser(userName);
            user.IsApproved = false;            
            user.Comment = Esapi.Randomizer.GetRandomGUID().ToString();
            Membership.UpdateUser(user);
            String activationUrl = Request.Url.ToString().Replace("Register.aspx", String.Format("Activate.aspx?username={0}&token={1}", userName, user.Comment));
            String body = FileUtil.RetrieveFileBody("ActivationBody.txt").Replace("@ActivationUrl", activationUrl);
            MailUtil.SendMail(user.Email, "User Activation Email", body);
            Response.Redirect("Message.aspx?message=3");
        }
    }
}
