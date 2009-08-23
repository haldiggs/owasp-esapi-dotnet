using System;
using System.Web.UI.WebControls;
using Owasp.Esapi.ValidationRules;

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
            args.IsValid = Esapi.Validator.IsValid(BuiltinValidationRules.CreditCard, args.Value);
            lblCreditCardSuccess.Visible = args.IsValid;            
        }
        protected void vldDate_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(BuiltinValidationRules.Date, args.Value);
            lblDateSuccess.Visible = args.IsValid;
        }

        protected void vldDouble_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(BuiltinValidationRules.Double, args.Value);
            lblDoubleSuccess.Visible = args.IsValid;
        }

        protected void vldInteger_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(BuiltinValidationRules.Integer, args.Value);
            lblIntegerSuccess.Visible = args.IsValid;
        }

        protected void vldPrintable_ServerValidate(object source, ServerValidateEventArgs args)
        {
            args.IsValid = Esapi.Validator.IsValid(BuiltinValidationRules.Printable, args.Value);
            lblPrintableSuccess.Visible = args.IsValid;
        }
    }
}
