using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class performs date validation.
    /// </summary>
    [ValidationRule(BuiltinValidationRules.Date)]
    public class DateValidationRule : IValidationRule
    {        

        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid date.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
        public bool IsValid(string input)
        {
            DateTime value;
            return DateTime.TryParse(input, out value);
        }

        #endregion
    }
}
