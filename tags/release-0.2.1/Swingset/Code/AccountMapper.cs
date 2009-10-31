using System;
using System.Data;
using System.Web;
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
            HttpContext.Current.Session["AccountMapper"] = this;
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
            foreach (Account account in arm.GetDirectReferences())
            {
               DataRow row = table.NewRow();
               row["reference"] = arm.GetIndirectReference(account);
               row["name"] = account.Name;
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
