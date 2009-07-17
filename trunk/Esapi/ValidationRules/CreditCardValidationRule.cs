using System;
using System.Text;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class CreditCardValidationRule:IValidationRule
    {
     
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            if (input == null) return false;

            // perform Luhn algorithm checking
            StringBuilder digitsOnly = new StringBuilder();
            char c;
            for (int i = 0; i < input.Length; i++)
            {
                c = input[i];
                if (Char.IsDigit(c))
                {
                    digitsOnly.Append(c);
                }
            }

            if (digitsOnly.Length > 18 || digitsOnly.Length < 15)
            {
                return false;
            }
            int sum = 0;
            int digit = 0;
            int addend = 0;
            bool timesTwo = false;

            for (int i = digitsOnly.Length - 1; i >= 0; i--)
            {
                digit = Int32.Parse(digitsOnly.ToString(i, 1));
                if (timesTwo)
                {
                    addend = digit * 2;
                    if (addend > 9)
                    {
                        addend -= 9;
                    }
                }
                else
                {
                    addend = digit;
                }
                sum += addend;
                timesTwo = !timesTwo;
            }

            int modulus = sum % 10;
            return (modulus == 0);
        }

        #endregion
    }
}
