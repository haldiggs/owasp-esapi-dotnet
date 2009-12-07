using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context bound rule
    /// </summary>
    public interface IContextRule
    {
        /// <summary>
        /// Rule to execute
        /// </summary>
        IRule Rule { get; }
        /// <summary>
        /// Actions to run if the rule execution fails
        /// </summary>
        ICollection<IAction> FaultActions { get; }
    }

    /// <summary>
    /// Context bound conditions
    /// </summary>
    public interface IContextCondition
    {
        /// <summary>
        /// Condition to evaluate
        /// </summary>
        ICondition Condition { get; }
        /// <summary>
        /// Evaluation value to match
        /// </summary>
        bool Result { get; set; }
    }

    /// <summary>
    /// Context interface
    /// </summary>
    public interface IContext
    {
        /// <summary>
        /// Context unique name
        /// </summary>
        string Name { get; }
        /// <summary>
        /// Conditions to match for context to match
        /// </summary>
        ICollection<IContextCondition> MatchConditions { get; }
        /// <summary>
        /// Rules to execute if the context matches
        /// </summary>
        ICollection<IContextRule> ExecuteRules { get; }
        /// <summary>
        /// Subcontext collection
        /// </summary>
        ICollection<IContext> SubContexts { get; }

        /// <summary>
        /// Bind condition to context
        /// </summary>
        /// <param name="condition"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        IContextCondition BindCondition(ICondition condition, bool result);
        /// <summary>
        /// Bind rule to context
        /// </summary>
        /// <param name="rule"></param>
        /// <returns></returns>
        IContextRule BindRule(IRule rule);
        /// <summary>
        /// Add a new subcontext
        /// </summary>
        /// <returns></returns>
        /// <remarks>Sub context name is automatically generated</remarks>
        IContext CreateSubContext();
        /// <summary>
        /// Add a new named subcontext
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        IContext CreateSubContext(string name);
        /// <summary>
        /// Lookup subcontext by name
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        IContext LookupSubContext(string name);
        /// <summary>
        /// Register subcontext
        /// </summary>
        /// <param name="name"></param>
        /// <param name="context"></param>
        void RegisterSubContext(string name, IContext context);
    }
}
