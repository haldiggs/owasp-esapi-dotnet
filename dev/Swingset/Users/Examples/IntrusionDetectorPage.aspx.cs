using System;
using Owasp.Esapi.Runtime;
using Owasp.Esapi.Runtime.Rules;
using Owasp.Esapi.Runtime.Actions;
using System.Web.UI.WebControls;

namespace Owasp.Esapi.Swingset.Users.Examples
{
    /// <summary>
    /// Protect page with clickjack rule
    /// </summary>
    [RunRule(typeof(ClickjackRule), new Type[] { typeof(LogAction), typeof(LogoutAction)})]
    public partial class IntrusionDetectorPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnAddSecurityEvent_Click(object sender, EventArgs e)
        {
            Esapi.IntrusionDetector.AddEvent("test");
        }
    }
}
