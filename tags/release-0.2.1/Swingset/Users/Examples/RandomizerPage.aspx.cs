using System;

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
            txtString.Text = Esapi.Randomizer.GetRandomString(16, Owasp.Esapi.CharSetValues.Alphanumerics);
            txtFilename.Text = Esapi.Randomizer.GetRandomFilename("esapi");
        }
    }
}
