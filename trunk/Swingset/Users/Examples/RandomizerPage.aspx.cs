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
    public partial class RandomizerPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {


        }

        protected void btnGenerate_Click(object sender, EventArgs e)
        {
            txtbool.Text = Esapi.Randomizer.GetRandomBoolean().ToString();
            txtGuid.Text = Esapi.Randomizer.GetRandomGUID().ToString();
            txtInteger.Text = Esapi.Randomizer.GetRandomInteger(Int32.MinValue, Int32.MaxValue).ToString();
            txtDouble.Text = Esapi.Randomizer.GetRandomDouble(0, 1).ToString();
            txtString.Text = Esapi.Randomizer.GetRandomString(16, Owasp.Esapi.Encoder.CHAR_ALPHANUMERICS);
            txtFilename.Text = Esapi.Randomizer.GetRandomFilename("esapi");
        }
    }
}
