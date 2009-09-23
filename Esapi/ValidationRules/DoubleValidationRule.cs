using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class performs double (decimal) validation.
    /// </summary>
    [ValidationRule(BuiltinValidationRules.Double)]
    public class DoubleValidationRule : IValidationRule
    {
        private double _minValue = double.MinValue;
        private double _maxValue = double.MaxValue;

        /// <summary>
        /// Minimum value
        /// </summary>
        public double MinValue
        {
            get { return _minValue; }
            set { _minValue = value; }
        }

        /// <summary>
        /// Maximum value
        /// </summary>
        public double MaxValue
        {
            get { return _maxValue; }
            set { _maxValue = value; }
        }

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

            return !(Double.IsInfinity(value) || Double.IsNaN(value)) &&
                 (value >= _minValue && value <= _maxValue);
        }
        
        #endregion
    }
}
