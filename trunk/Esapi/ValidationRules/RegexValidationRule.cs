using System.Text.RegularExpressions;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    /// <summary>
    /// This class is for validating that text is valid according to a given regular expression pattern.
    /// </summary>
    class RegexValidationRule:IValidationRule
    {
        Regex regex;
        
        /// <summary>
        /// Constructor that accepts regular expression.
        /// </summary>
        /// <param name="_regex">The regular expression to validate against.</param>
        public RegexValidationRule(string _regex)
        {            
            regex = new Regex(_regex);
        }

        #region IValidationRule Members

        /// <summary>
        /// Checks whether the input is a valid against the specified regular expression.
        /// </summary>
        /// <param name="input">The input to valdiate.</param>
        /// <returns>True, if the input is valid. False, otherwise.</returns>
        public bool IsValid(string input)
        {
            if (input == null) {
                return false;
            }

            return regex.IsMatch(input, 0);
        }

        #endregion

    }
}
