using System;
using System.Collections.Generic;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.IValidator" />
    /// <summary>
    /// Reference implementation of the <see cref="Owasp.Esapi.IValidator"/> interface. This implementation
    /// keeps the validation rules in a map. It also adds the default set of validation rules defined in the reference 
    /// implementation.
    /// </summary>
    public class Validator : IValidator
    {
        private Dictionary<string, IValidationRule> rules = new Dictionary<string, IValidationRule>();

        /// <inheritdoc cref="Owasp.Esapi.IValidator.AddRule(string, IValidationRule)" />
        public void AddRule(string name, IValidationRule rule)
        {
            // NOTE: "name" will be validated by the dictionary
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }
            rules.Add(name, rule);
        }

        /// <inheritdoc cref="Owasp.Esapi.IValidator.GetRule(string)" />
        public IValidationRule GetRule(string name)
        {
            if (name == null) {
                throw new ArgumentNullException("name");
            }
            
            IValidationRule rule;
            rules.TryGetValue(name, out rule);

            return rule;
        }

        /// <inheritdoc cref="Owasp.Esapi.IValidator.RemoveRule(string)" />
        public void RemoveRule(string name)
        {
            if (name == null) {
                throw new ArgumentNullException("name");
            }
            rules.Remove(name);
        }

        /// <inheritdoc cref="Owasp.Esapi.IValidator.IsValid(string, string)" />
        public bool IsValid(string ruleName, string input)
        {
            if (ruleName == null) {
                throw new ArgumentNullException("ruleName");
            }

            return GetRule(ruleName).IsValid(input);
        }
    }
}
