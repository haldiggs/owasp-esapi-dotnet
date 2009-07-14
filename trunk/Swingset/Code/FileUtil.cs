using System;
using System.Data;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;
using System.IO;

namespace Owasp.Esapi.Swingset
{
    public class FileUtil
    {
        public static string RetrieveFileBody(string FileName)
        {
            String exactFileName = String.Format("~/App_Data/{0}", Path.GetFileName(FileName));
            return File.ReadAllText(HttpContext.Current.Server.MapPath(exactFileName));           
        }
    }
}
