using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Swingset
{
    public class SwingsetPage:System.Web.UI.Page
    {
        public ILogger logger = Esapi.Logger;
        
        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            Esapi.HttpUtilities.AddCsrfToken();
            Esapi.HttpUtilities.AddNoCacheHeaders();
        }
    }
}
