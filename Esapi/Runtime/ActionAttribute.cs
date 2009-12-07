using System;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Action attribute
    /// </summary>
    /// <remarks>
    /// Marks as class as an action; the class has to implement IAction
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class ActionAttribute : AddinAttribute
    {
        /// <summary>
        /// Initialize action attribute
        /// </summary>
        /// <param name="name">Action unique name</param>
        public ActionAttribute(string name)
            : base(name)
        {
        }
    }

    /// <summary>
    /// Rule attribute
    /// </summary>
    /// <remarks>
    /// Marks as class as a rule; the class has to implement IRule
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class RuleAttribute : AddinAttribute
    {
        /// <summary>
        /// Initialize rule attribute
        /// </summary>
        /// <param name="name">Rule unique name</param>
        public RuleAttribute(string name)
            : base(name)
        {
        }
    }

    /// <summary>
    /// Condition attribute
    /// </summary>
    /// <remarks>
    /// Marks as class as a condition ; the class has to implement IRule
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class ConditionAttribute : AddinAttribute
    {
        /// <summary>
        /// Initialize condition attribute
        /// </summary>
        /// <param name="name">Condition unique name</param>
        public ConditionAttribute(string name)
            : base(name)
        {
        }
    }
}
