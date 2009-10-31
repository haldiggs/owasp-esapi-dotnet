using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class is for validating that text is valid printable ASCII characters.
    /// </summary>
    [ValidationRule(BuiltinValidationRules.Printable)]
    public class PrintableValidationRule : IValidationRule
    {        
        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid printable character.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
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
