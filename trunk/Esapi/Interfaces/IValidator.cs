
namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// The Validator interface defines a set of methods for validating untrusted input. 
    /// Implementors should feel free to extend this interface to accommodate their own data formats. 
    /// Rather than throw exceptions, this interface returns boolean results because not all validation 
    /// problems are security issues. Boolean returns allow developers to handle both valid and invalid 
    /// results more cleanly than exceptions.  
    ///  
    /// Implementations must adopt a "whitelist" approach to validation where a specific pattern or character
    /// set is matched. "Blacklist" approaches that  attempt to identify the invalid or disallowed characters 
    /// are much more likely to allow a bypass with encoding or other tricks. 
    /// </summary>
    public interface IValidator
    {
        /// <summary>
        /// Checks whether input is valid according to a given rule. The rule is determined by passing a rule
        /// name key, which is used to identify a particular ValidationRule object.
        /// </summary>
        /// <param name="rule">The rule name key to use for validation.</param>
        /// <param name="input">The input to validate.</param>
        /// <returns>True, if the data is valid. False, otherwise.</returns>
        bool IsValid(string rule, string input);

        /// <summary>
        /// Adds a rule object with the associated rule name key. This rule can be used to
        /// validate data later using the <see cref="Owasp.Esapi.Interfaces.IValidator.IsValid(string, string)"/> method.
        /// </summary>
        /// <param name="name">The rule name key to use for the new rule.</param>
        /// <param name="rule">
        ///     The rule object, which implements <see cref="Owasp.Esapi.Interfaces.IValidationRule"/>
        /// </param>
        void AddRule(string name, IValidationRule rule);

        /// <summary>
        /// Returns the rule object with the specified key.
        /// </summary>
        /// <param name="name">The rule name key to lookuip.</param>
        /// <returns>
        /// The <see cref="Owasp.Esapi.Interfaces.IValidationRule"/> object associated witht the rule name
        /// key
        /// </returns>
        IValidationRule GetRule(string name);

        /// <summary>
        /// Removes the rule object with the specified key.
        /// </summary>
        /// <param name="name">The rule name key for the rule to remove</param>
        void RemoveRule(string name);
    }
}
