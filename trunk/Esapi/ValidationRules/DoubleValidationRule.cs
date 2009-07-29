using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class DoubleValidationRule : IValidationRule
    {        
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            double value;

            if (!double.TryParse(input, out value)) {
                return false;
            }

            return !(Double.IsInfinity(value) || Double.IsNaN(value));
        }
        
        #endregion
    }
}
