using System;

namespace Owasp.Esapi.Swingset.Users.Examples
{
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
