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
        private DateTime _minValue = DateTime.MinValue;
        private DateTime _maxValue = DateTime.MaxValue;

        /// <summary>
        /// Date min value
        /// </summary>
        public DateTime MinValue
        {
            get { return _minValue;  }
            set { _minValue = value; }
        }

        /// <summary>
        /// Date maximum value
        /// </summary>
        public DateTime MaxValue
        {
            get { return _maxValue;  }
            set { _maxValue = value; }
        }

        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid date.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
        public bool IsValid(string input)
        {
            DateTime value;
            if (!DateTime.TryParse(input, out value)) {
                return false;
            }

            return (value >= _minValue && value <= _maxValue);
        }

        #endregion
    }
}
