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
using System.Collections;
namespace Owasp.Esapi.Swingset
{
    public class AccountMapper
    {
        AccessReferenceMap arm = new AccessReferenceMap();

        public AccountMapper()
        {
            Account account1 = new Account(1, "My Checking", 100000);
            Account account2 = new Account(2, "My Savings", 100000);
            Account account3 = new Account(3, "My Investments", 100000);
            Account account4 = new Account(4, "Not allowed", 100000);
            arm.AddDirectReference(account1);
            arm.AddDirectReference(account2);
            arm.AddDirectReference(account3);
        }
        public DataTable GetAccountReferences()
        {
            DataTable table = new DataTable();
            DataColumn column;
            column = new DataColumn();
            column.DataType = Type.GetType("System.String");
            column.ColumnName = "reference";
            table.Columns.Add(column);

            column = new DataColumn();
            column.DataType = Type.GetType("System.String");
            column.ColumnName = "name";
            table.Columns.Add(column);
            foreach (string reference in arm.GetIndirectReferences())
            {
               DataRow row = table.NewRow();
               row["reference"] = reference;
               row["name"] = ((Account) arm.GetDirectReference(reference)).Name;
               table.Rows.Add(row);
            }
            return table;
        }

        public Account GetAccountFromReference(string reference)
        {
            return (Account) arm.GetDirectReference(reference);
        }        
    }
}
