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
    public partial class EncoderPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            
        }

        protected void btnEncode_Click(object sender, EventArgs e)
        {
            String text = txtToEncode.Text;
            txtHtml.Text = Esapi.Encoder.EncodeForHtml(text);
            txtHtmlAttribute.Text = Esapi.Encoder.EncodeForHtmlAttribute(text);
            txtJavascript.Text = Esapi.Encoder.EncodeForJavascript(text);
            txtVbScript.Text = Esapi.Encoder.EncodeForVbScript(text);
            txtXml.Text = Esapi.Encoder.EncodeForXml(text);
            txtXmlAttribute.Text = Esapi.Encoder.EncodeForXmlAttribute(text);            
        }
    }
}
