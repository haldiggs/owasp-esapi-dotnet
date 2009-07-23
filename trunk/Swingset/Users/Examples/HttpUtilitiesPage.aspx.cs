using System;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi.Swingset.Users.Examples
{
    public partial class HttpUtilitiesPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            lblSessionId.Text = Session.SessionID;
            int length = Request.Url.ToString().IndexOf('?');
            if (length < 0)
            {
                length = Request.Url.ToString().Length;
            }
            string url = Esapi.HttpUtilities.AddCsrfToken(Request.Url.ToString().Substring(0,length));
            hlCsrf.NavigateUrl = url;
            hlCsrf.Text = url;
            if (Request.QueryString["CsrfToken"] != null)
            {                
                try
                {
                    Esapi.HttpUtilities.VerifyCsrfToken();
                    lblCsrf.Text = "The CSRF token check succeeded";
                }
                catch (IntrusionException)
                {
                    lblCsrf.Text = "The CSRF token check failed";
                }

            }
        }

        protected void btnChangeSessionId_Click(object sender, EventArgs e)
        {
            Esapi.HttpUtilities.ChangeSessionIdentifier();
            lblSessionId.Text = Response.Cookies[".ESAPI_SESSIONID"].Value;
        }
    }
}
