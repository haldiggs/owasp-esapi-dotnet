using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class IntegerValidationRule:IValidationRule
    {
        
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            int value;
            return int.TryParse(input, out value);
        }

        #endregion
    }
}
