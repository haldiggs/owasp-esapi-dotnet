using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class is for validating that text is valid printable ASCII characters.
    /// </summary>
    class PrintableValidationRule : IValidationRule
    {        
        #region IValidationRule Members

        /// <inheritdocs cref="Owasp.Esapi.Interfaces.IValidationRule.IsValid(string)"/>
        /// <remarks>
        /// This method checks whehter or not the input contains only valid printable ASCII characters.
        /// </remarks>
        public bool IsValid(string input)
        {
            if (input == null) {
                return false;
            }
            if (input.Length == 0) {
                return true;
            }

            for (int i = 0; i < input.Length; i++) {
                if (input[i] < 33 || input[i] > 126) {
                    return false;
                }
            }

            return true;
        }

        #endregion
    }
}
