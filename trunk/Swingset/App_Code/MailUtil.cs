using System;
using System.Data;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;
using System.Net.Mail;

namespace Owasp.Esapi.Swingset
{
    public class MailUtil
    {

        public static void SendMail(String EmailAddress, String Subject, String Body)
        {
            MailMessage mailMessage = new MailMessage();
            mailMessage.To.Add(EmailAddress);
            mailMessage.Subject = Subject;
            mailMessage.Body = Body;
            mailMessage.IsBodyHtml = false;
            SmtpClient smtp = new SmtpClient();
            smtp.Send(mailMessage);
        }
    }
}
