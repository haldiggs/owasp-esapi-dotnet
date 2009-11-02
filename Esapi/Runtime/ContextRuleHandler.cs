using System;
using System.Collections.Generic;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context bound rule
    /// </summary>
    /// <remarks>Bounds a rule execution to a context</remarks>
    public class ContextBoundRule
    {
        private IRule _rule;
        private ContextActionsHandler _actions;
        private HashSet<string> _events;

        /// <summary>
        /// Initialize context bound rule
        /// </summary>
        /// <param name="rule"></param>
        public ContextBoundRule(IRule rule)
            : this(rule, null)
        {
        }
        /// <summary>
        /// Initialize context bound rule
        /// </summary>
        /// <param name="rule"></param>
        /// <param name="events"></param>
        public ContextBoundRule(IRule rule, IEnumerable<string> events)
        {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }
            
            _rule = rule;
            _actions = new ContextActionsHandler();
            _events = (events != null ? new HashSet<string>(events) : new HashSet<string>());
        }
        /// <summary>
        /// Rule
        /// </summary>
        public IRule Rule
        {
            get { return _rule; }
        }
        /// <summary>
        /// Fault actions
        /// </summary>
        public ICollection<ContextBoundAction> FaultActions
        {
            get { return _actions; }
        }
        /// <summary>
        /// Events that trigger the rule
        /// </summary>
        public ICollection<string> Events
        {
            get { return _events; }
        }        
    }   
}
