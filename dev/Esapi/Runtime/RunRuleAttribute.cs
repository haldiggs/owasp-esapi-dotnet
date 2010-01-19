using System;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Request rule execution at runtime
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = true)]
    public class RunRuleAttribute : Attribute
    {
        private Type _ruleType;
        private Type[] _faultActions;

        /// <summary>
        /// Initialize required rule to run
        /// </summary>
        /// <param name="ruleType">Rule type</param>
        public RunRuleAttribute(Type ruleType)
            : this(ruleType, null)
        {
        }
        /// <summary>
        /// Initialize required rule to run
        /// </summary>
        /// <param name="ruleType">Rule type</param>
        /// <param name="faultActions">Actions to run on rule failure</param>
        public RunRuleAttribute(Type ruleType, Type[] faultActions)
        {
            if (ruleType == null) {
                throw new ArgumentNullException();
            }
            _ruleType = ruleType;
            _faultActions = faultActions;
        }
        /// <summary>
        /// Type of rule to run
        /// </summary>
        public Type Rule
        {
            get { return _ruleType; }
            set
            {
                if (value == null) {
                    throw new ArgumentNullException();
                }
                _ruleType = value;
            }
        }
        /// <summary>
        /// Actions to run if the rule fails
        /// </summary>
        public Type[] FaultActions
        {
            get { return _faultActions; }
            set { _faultActions = value; }
        }
    }
}
