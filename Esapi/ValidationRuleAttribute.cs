using System;

namespace Owasp.Esapi
{
    /// <summary>
    /// Validation rule attribute
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class ValidationRuleAttribute : Attribute
    {
        private readonly string _name;
        private bool _autoLoad;
        
        /// <summary>
        /// Initialize validation rule attribute
        /// </summary>
        /// <param name="name">Rule unique name</param>
        public ValidationRuleAttribute(string name) 
        {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException();
            }

            _name     = name;
            _autoLoad = true;
        }
       
        /// <summary>
        /// Rule unique name
        /// </summary>
        public string Name
        {
            get { return _name; }
        }

        /// <summary>
        /// Validation rule can be loaded automatically
        /// </summary>
        /// <remarks>Set to false if the rule requires initialization parameters</remarks>
        public bool AutoLoad
        {
            get { return _autoLoad; }
            set { _autoLoad = value; }
        }
    }
}
