using System;
using System.Collections.Generic;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.ValidationRules;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.IValidator" />
    /// <remarks>
    /// The default implementation of the <see href="Owasp.Esapi.Interfaces.IValidator"/> interface. This implementation
    /// keeps the validation rules in a map. It also adds the default set of validation rules defined in the reference 
    /// implementation.
    /// </remarks>
    public class Validator:IValidator
    {
        /// <summary>
        /// Rule name key for the credit card validation rule.
        /// </summary>
        public static readonly string CREDIT_CARD = "CreditCard";

        /// <summary>
        /// Rule name key for the date validation rule.
        /// </summary>
        public static readonly string DATE = "Date";

        /// <summary>
        /// Rule name key for the double validation rule.
        /// </summary>
        public static readonly string DOUBLE = "Double";

        /// <summary>
        /// Rule name key for the integer validation rule.
        /// </summary>
        public static readonly string INTEGER = "Integer";

        /// <summary>
        /// Rule name key for the printable validation rule.
        /// </summary>
        public static readonly string PRINTABLE = "Printable";

        private Dictionary<string, IValidationRule> rules = new Dictionary<string, IValidationRule>();

        /// <summary>
        /// Default constructor, adds the default rules.
        /// </summary>
        public Validator()
        {
            AddRule(CREDIT_CARD, new CreditCardValidationRule());
            AddRule(DATE, new DateValidationRule());
            AddRule(DOUBLE, new DoubleValidationRule());
            AddRule(INTEGER, new IntegerValidationRule());
            AddRule(PRINTABLE, new PrintableValidationRule());
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IValidator.AddRule(string, IValidationRule)" />
        public void AddRule(string name, IValidationRule rule)
        {
            // NOTE: "name" will be validated by the dictionary
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }
            rules.Add(name, rule);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IValidator.GetRule(string)" />
        public IValidationRule GetRule(string name)
        {
            if (name == null) {
                throw new ArgumentNullException("name");
            }
            
            IValidationRule rule;
            rules.TryGetValue(name, out rule);

            return rule;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IValidator.RemoveRule(string)" />
        public void RemoveRule(string name)
        {
            if (name == null) {
                throw new ArgumentNullException("name");
            }
            rules.Remove(name);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IValidator.IsValid(string, string)" />
        public bool IsValid(string ruleName, string input)
        {
            if (ruleName == null) {
                throw new ArgumentNullException("ruleName");
            }

            return GetRule(ruleName).IsValid(input);
        }
    }
}
