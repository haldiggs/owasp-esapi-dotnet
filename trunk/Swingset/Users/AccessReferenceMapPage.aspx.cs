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

namespace Owasp.Esapi.Swingset.Users
{

    class Account
    {
        int id;

        public int Id
        {
            get { return id; }
            set { id = value; }
        }
        double amt;

        public double Amt
        {
            get { return amt; }
            set { amt = value; }
        }

        public Account(int _id, double _amt)
        {
            Id = _id;
            Amt = _amt;
        }
    }

    public class Accounts 
    {
        AccessReferenceMap arm = new AccessReferenceMap();
        
        public Accounts()
        {          
            Account account1 = new Account(1, 100000);
            Account account2 = new Account(1, 100000);
            Account account3 = new Account(1, 100000);
            arm.AddDirectReference(account1);
            arm.AddDirectReference(account2);
            arm.AddDirectReference(account3);
        }
        public ArrayList GetAccountReferences()
        {
            return new ArrayList(arm.GetIndirectReferences());
        }

        public ArrayList GetAccountFromReference(string reference)
        {
            return new ArrayList(arm.GetIndirectReferences());
        }
    }


    public partial class AccessReferenceMapPage : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            
        }
    }
}
