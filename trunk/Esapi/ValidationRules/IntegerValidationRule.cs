using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class performs integer validation.
    /// </summary>
    [ValidationRule(BuiltinValidationRules.Integer)]
    public class IntegerValidationRule : IValidationRule
    {
        
        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid integer.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
        public bool IsValid(string input)
        {
            int value;
            return int.TryParse(input, out value);
        }

        #endregion
    }
}
