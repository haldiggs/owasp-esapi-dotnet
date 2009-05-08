using System;
using System.Collections;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;

namespace Owasp.Esapi.Swingset
{
    public partial class Message : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string message = Request.QueryString.Get("message");
            if (message != null)
            {
                switch (message)
                {
                    case "1":
                        lblMessage.Text = "You have successfully activated your account.";
                        break;
                    case "2":
                        lblMessage.Text = "You have successfully reset your password.";
                        break;
                    case "3":
                        lblMessage.Text = "Your account has been successfully created. Please check your email for a message that will help you activate your account.";
                        break;
                    case "4":
                        lblMessage.Text = "If the username you supplied exists, you will be sent an email with activation instructions.";
                        break;
                }
            }
        }
    }
}
