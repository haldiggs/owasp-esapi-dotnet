using System.Collections.Generic;
using System;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context
    /// </summary>
    /// TODO: contexts, bound rules, conditions and actions should have names
    /// TODO: add fluent interface
    /// TODO: load runtime from configuration
    /// TODO: better logging at evaluation time
    public class Context : IContextHandler
    {
        private string _name;

        private ContextConditionsHandler _conditions;
        private ContextRulesHandler _rules;
        private ContextCollectionHandler _subcontexts;

        /// <summary>
        /// Initialize context
        /// </summary>
        public Context(string name)
        {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("Invalid name", "name");
            }

            _name = name;
            _conditions = new ContextConditionsHandler();
            _rules = new ContextRulesHandler();
            _subcontexts = new ContextCollectionHandler();
        }
        /// <summary>
        /// Context unique ID
        /// </summary>
        public string Name
        {
            get { return _name; }
        }
        /// <summary>
        /// Conditions to match
        /// </summary>
        public ICollection<ContextBoundCondition> MatchConditions
        {
            get { return _conditions; }
        }
        /// <summary>
        /// Rules to execute
        /// </summary>
        public ICollection<ContextBoundRule> ExecuteRules
        {
            get { return _rules; }
        }
        /// <summary>
        /// Dependent contexts
        /// </summary>
        public ICollection<Context> SubContexts
        {
            get { return _subcontexts; }
        }
        /// <summary>
        /// Register subcontext
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public Context RegisterContext(string name)
        {
            if (_subcontexts.Contains(name)) {
                throw new ArgumentException("Duplicate name", "name");
            }

            Context context = new Context(name);
            _subcontexts.Add(context);

            return context;
        }

        #region IContextHandler Members
        /// <summary>
        /// Process context event
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        bool IContextHandler.ProcessEvent(ContextEvent args)
        {
            if (!_conditions.ProcessEvent(args)) {
                return false;
            }

            _rules.ProcessEvent(args);
            _subcontexts.ProcessEvent(args);

            return true;
        }

        #endregion
    }    
}
