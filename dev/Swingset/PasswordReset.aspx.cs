using System;
using System.Web.Security;
using System.Web.UI;

namespace Owasp.Esapi.Swingset
{
    public partial class PasswordReset : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {            
            string userName = Request.QueryString.Get("username");
            string resetGuid = Request.QueryString.Get("token");
            MembershipUser user = Membership.GetUser(userName);
            if (user == null)
            {
                logger.Info(LogEventTypes.SECURITY, String.Format("Non-existent User {0} unsuccessfully attempted to reset password.", userName));
            } else if (!user.IsApproved)
            {
                logger.Info(LogEventTypes.SECURITY, String.Format("Non-active User {0} unsuccessfully attempted to reset password.", userName));
            }
            else if (!(user.Comment == resetGuid))
            {
                logger.Info(LogEventTypes.SECURITY, String.Format("User {0} unsuccessfully attempted to reset password (bad token).", userName));
            }
            else
            {
                logger.Info(LogEventTypes.SECURITY, String.Format("User {0} successfully accessed reset password form.", userName));
                lblSecretQuestion.Text = user.PasswordQuestion;
                Context.Items["user"] = user;
                return;
            }
            Response.Redirect("Error.aspx");            
        }

        protected void btnSubmit_Click(object sender, EventArgs e)
        {
            if (Page.IsValid)
            {
                MembershipUser user = (MembershipUser)Context.Items["user"];
                string secretAnswer = txtSecretAnswer.Text;
                string tempPassword = null;
                try
                {
                    tempPassword = user.ResetPassword(secretAnswer);
                    logger.Info(LogEventTypes.SECURITY, String.Format("User {0} supplied the correct answer to the secret question.", user.UserName));
                }
                catch (MembershipPasswordException mpe)
                {
                    lblError.Text = "The answer to the secret question was not correct.";
                    logger.Warning(LogEventTypes.SECURITY, String.Format("User {0} supplied the wrong answer to the secret question.", user.UserName), mpe);
                }
                if (tempPassword != null)
                {
                    string newPassword = txtNewPassword.Text;
                    user.ChangePassword(tempPassword, txtNewPassword.Text);
                    user.Comment = null;
                    Membership.UpdateUser(user);
                    logger.Info(LogEventTypes.SECURITY, String.Format("User {0} successfully changed their password.", user.UserName));
                    Response.Redirect("Message.aspx?message=2");
                }
            }
        }
    }
}
