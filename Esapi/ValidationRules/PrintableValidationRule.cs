using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.ValidationRules
{
    class PrintableValidationRule:IValidationRule
    {        

        #region IValidationRule Members

        public bool IsValid(string input)
        {
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] < 33 || input[i] > 126)
                {
                    return false;
                }
            }
            return true;
        }

        #endregion
    }
}
