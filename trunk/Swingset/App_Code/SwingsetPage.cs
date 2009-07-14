using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Swingset
{
    public class SwingsetPage:System.Web.UI.Page
    {
        public ILogger logger = Esapi.Logger;
        
        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            ViewStateUserKey = Session.SessionID;
        }
    }
}
