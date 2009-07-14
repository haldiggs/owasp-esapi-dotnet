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
using Owasp.Esapi.Errors;

namespace Owasp.Esapi.Swingset.Users.Examples
{
    public partial class AccessReferenceMapPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string id = Request.QueryString["id"]; 
            if (id != null)
            
            {
                if (!Esapi.Validator.IsValid(Owasp.Esapi.Validator.PRINTABLE, Request.QueryString["id"]))
                {
                    throw new ValidationException("The parameter value supplied was not valid.", "The ID parameter to the AccessReferenceMap page was not valid.");
                }
                Account account = new AccountMapper().GetAccountFromReference(id);
                lblAccountInfo.Text = String.Format("Name: {0}, Amt: {1}", account.Name, account.Amt);            
            }
            
            
        }
    }
}
