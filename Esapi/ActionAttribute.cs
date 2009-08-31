using System;

namespace Owasp.Esapi
{
    /// <summary>
    /// Action attribute
    /// </summary>
    /// <remarks>
    /// Marks as class as an action; the class has to implement IAction
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class ActionAttribute : NamedAddinAttribute
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
}
