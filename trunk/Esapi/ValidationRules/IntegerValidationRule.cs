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
        private int _minValue = int.MinValue;
        private int _maxValue = int.MaxValue;

        /// <summary>
        /// Minimum value
        /// </summary>
        public int MinValue
        {
            get { return _minValue; }
            set { _minValue = value; }
        }

        /// <summary>
        /// Maximum value
        /// </summary>
        public int MaxValue
        {
            get { return _maxValue; }
            set { _maxValue = value; }
        }
        
        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid integer.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
        public bool IsValid(string input)
        {
            int value;
            if (!int.TryParse(input, out value)) {
                return false;
            }

            return (value >= _minValue && value <= _maxValue);
        }

        #endregion
    }
}
