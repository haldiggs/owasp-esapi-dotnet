using System;
using Owasp.Esapi.Codecs;

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
            txtHtml.Text = Esapi.Encoder.Encode(BuiltinCodecs.Html, text);
            txtHtmlAttribute.Text = Esapi.Encoder.Encode(BuiltinCodecs.HtmlAttribute, text);
            txtJavascript.Text = Esapi.Encoder.Encode(BuiltinCodecs.JavaScript, text);
            txtVbScript.Text = Esapi.Encoder.Encode(BuiltinCodecs.VbScript, text);
            txtXml.Text = Esapi.Encoder.Encode(BuiltinCodecs.Xml, text);
            txtXmlAttribute.Text = Esapi.Encoder.Encode(BuiltinCodecs.XmlAttribute, text);            
        }
    }
}
