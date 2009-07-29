using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class DateValidationRule:IValidationRule
    {        

        #region IValidationRule Members

        public bool IsValid(string input)
        {
            DateTime value;
            return DateTime.TryParse(input, out value);
        }

        #endregion
    }
}
