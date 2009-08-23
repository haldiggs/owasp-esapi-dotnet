using System;
using System.Text;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class performs credit card number validation, including Luhn algorithm checking.
    /// </summary>
    [ValidationRule(BuiltinValidationRules.CreditCard)]
    public class CreditCardValidationRule : IValidationRule
    {
        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid credit card number.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
        public bool IsValid(string input)
        {
            if (string.IsNullOrEmpty(input)) {
                return false;
            }
            
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
