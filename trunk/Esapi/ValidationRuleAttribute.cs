using System;

namespace Owasp.Esapi
{
    /// <summary>
    /// Validation rule attribute
    /// </summary>
    /// <remarks>
    /// Marks a class as a validation rule; the class has to implement IValidationRule
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class ValidationRuleAttribute : AddinAttribute
    {
        /// <summary>
        /// Initialize validation rule attribute
        /// </summary>
        /// <param name="name">Rule unique name</param>
        public ValidationRuleAttribute(string name) 
            : base(name)
        {
        }
    }
}
