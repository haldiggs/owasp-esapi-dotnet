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
            txtHtml.Text = Esapi.Encoder.Encode(Encoder.HTML, text);
            txtHtmlAttribute.Text = Esapi.Encoder.Encode(Encoder.HTML_ATTRIBUTE, text);
            txtJavascript.Text = Esapi.Encoder.Encode(Encoder.JAVASCRIPT, text);
            txtVbScript.Text = Esapi.Encoder.Encode(Encoder.VBSCRIPT, text);
            txtXml.Text = Esapi.Encoder.Encode(Encoder.XML, text);
            txtXmlAttribute.Text = Esapi.Encoder.Encode(Encoder.XML_ATTRIBUTE, text);            
        }
    }
}
