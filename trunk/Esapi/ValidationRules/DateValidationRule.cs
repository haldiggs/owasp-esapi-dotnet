using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class DateValidationRule:IValidationRule
    {        
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            try
            {
                DateTime date = DateTime.Parse(input);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }

        }

        #endregion
    }
}
