
namespace Owasp.Esapi.Swingset
{
    public class Account
    {
        int id;

        public int Id
        {
            get { return id; }
            set { id = value; }
        }

        string name;

        public string Name
        {
            get { return name; }
            set { name = value; }
        }

        double amt;

        public double Amt
        {
            get { return amt; }
            set { amt = value; }
        }

        public Account(int _id, string _name, double _amt)
        {
            Id = _id;
            Name = _name;
            Amt = _amt;
        }    
    }
}
