using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class performs double (decimal) validation.
    /// </summary>
    class DoubleValidationRule : IValidationRule
    {        
        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid double.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
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
