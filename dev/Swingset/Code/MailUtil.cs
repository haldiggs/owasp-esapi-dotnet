using System;
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
