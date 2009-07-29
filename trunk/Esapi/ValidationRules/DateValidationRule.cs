using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class DateValidationRule:IValidationRule
    {        

        #region IValidationRule Members

        public bool IsValid(string input)
        {
            DateTime date;
            return DateTime.TryParse(input, out date);
        }

        #endregion
    }
}
