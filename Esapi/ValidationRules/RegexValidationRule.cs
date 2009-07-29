using System.Text.RegularExpressions;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class RegexValidationRule:IValidationRule
    {
        Regex regex;
        
        public RegexValidationRule(string _regex)
        {            
            regex = new Regex(_regex);
        }

        #region IValidationRule Members

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
