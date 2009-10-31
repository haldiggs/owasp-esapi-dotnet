using Owasp.Esapi.Interfaces;

namespace EsapiTest.Surrogates
{
    /// <summary>
    /// Forward validator
    /// </summary>
    internal class SurrogateValidator : IValidator
    {
        public static IValidator DefaultValidator;
        private IValidator _instanceValidator;

        public IValidator Impl
        {
            get { return _instanceValidator == null ? DefaultValidator : _instanceValidator; }
            set { _instanceValidator = value; }
        }

        #region IValidator Members

        public bool IsValid(string rule, string input)
        {
            return Impl.IsValid(rule, input);
        }

        public void AddRule(string name, IValidationRule rule)
        {
            Impl.AddRule(name, rule);
        }

        public IValidationRule GetRule(string name)
        {
            return Impl.GetRule(name);
        }

        public void RemoveRule(string name)
        {
            Impl.RemoveRule(name);
        }

        #endregion
    }
    /// <summary>
    /// Forward validation rule
    /// </summary>
    internal class SurrogateValidationRule : IValidationRule
    {
        public IValidationRule Implt { get; set; }
        #region IValidationRule Members

        public bool IsValid(string input)
        {
            return Implt.IsValid(input);
        }

        #endregion
    }
}
