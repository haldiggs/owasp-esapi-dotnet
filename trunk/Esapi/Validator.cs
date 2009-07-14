using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owasp.Esapi.Interfaces;
using System.Collections;
using Microsoft.Security.Application;
using Owasp.Esapi.ValidationRules;

namespace Owasp.Esapi
{
    public class Validator:IValidator
    {
        public static readonly string CREDIT_CARD = "CreditCard";
        public static readonly string DATE = "Date";
        public static readonly string DOUBLE = "Double";
        public static readonly string INTEGER = "Integer";
        public static readonly string PRINTABLE = "Printable";
        public Validator()
        {
            AddRule(CREDIT_CARD, new CreditCardValidationRule());
            AddRule(DATE, new DateValidationRule());            
            AddRule(DOUBLE, new DoubleValidationRule());
            AddRule(INTEGER, new IntegerValidationRule());
            AddRule(PRINTABLE, new PrintableValidationRule());
        }


        private Hashtable rules = new Hashtable();
        public void AddRule(string name, IValidationRule rule)
        {
            rules.Add(name, rule);
        }

        public IValidationRule GetRule(string name)
        {
            return (IValidationRule) rules[name];
        }

        public void RemoveRule(string name)
        {
            rules.Remove(name);
        }

        #region IValidator Members

        public bool IsValid(string ruleName, string input)
        {
            return GetRule(ruleName).IsValid(input);
        }
        
        #endregion
    }
}
