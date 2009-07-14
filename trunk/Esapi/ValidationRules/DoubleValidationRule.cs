using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class DoubleValidationRule:IValidationRule
    {        
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            try
            {
                Double d = Double.Parse(input);
                return !(Double.IsInfinity(d) || Double.IsNaN(d));
            }
            catch (FormatException)
            {
                return false;
            }

            
        }

        
        #endregion
    }
}
