using System;

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
