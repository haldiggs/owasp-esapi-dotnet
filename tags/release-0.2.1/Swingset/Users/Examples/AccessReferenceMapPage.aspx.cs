using System;
using Owasp.Esapi.Errors;
using Owasp.Esapi.ValidationRules;

namespace Owasp.Esapi.Swingset.Users.Examples
{
    public partial class AccessReferenceMapPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string id = Request.QueryString["id"]; 
            if (id != null)            
            {
                if (!Esapi.Validator.IsValid(BuiltinValidationRules.Printable, Request.QueryString["id"]))
                {
                    throw new ValidationException("The parameter value supplied was not valid.", "The ID parameter to the AccessReferenceMap page was not valid.");
                }
                Account account = ((AccountMapper) Session["AccountMapper"]).GetAccountFromReference(id);
                lblAccountInfo.Text = String.Format("Name: {0}, Amt: {1}", account.Name, account.Amt);
            }
        }
    }
}
