using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class IntegerValidationRule:IValidationRule
    {
        
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            try
            {
                int i = Int32.Parse(input);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
            catch (OverflowException)
            {
                return false;
            }
        }

        #endregion
    }
}
