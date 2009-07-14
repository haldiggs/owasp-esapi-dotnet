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

namespace Owasp.Esapi.Swingset.Users.Examples
{
    public partial class ValidatorPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            lblCreditCardSuccess.Visible = false;
            lblDateSuccess.Visible = false;
            lblDoubleSuccess.Visible = false;
            lblIntegerSuccess.Visible = false;
            lblPrintableSuccess.Visible = false;
        }

        protected void vldCreditCard_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(Owasp.Esapi.Validator.CREDIT_CARD, args.Value);
            lblCreditCardSuccess.Visible = args.IsValid;            
        }
        protected void vldDate_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(Owasp.Esapi.Validator.DATE, args.Value);
            lblDateSuccess.Visible = args.IsValid;
        }

        protected void vldDouble_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(Owasp.Esapi.Validator.DOUBLE, args.Value);
            lblDoubleSuccess.Visible = args.IsValid;
        }

        protected void vldInteger_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(Owasp.Esapi.Validator.INTEGER, args.Value);
            lblIntegerSuccess.Visible = args.IsValid;
        }

        protected void vldPrintable_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(Owasp.Esapi.Validator.PRINTABLE, args.Value);
            lblPrintableSuccess.Visible = args.IsValid;
        }
    }
}
