using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context bound action
    /// </summary>
    public class ContextBoundAction
    {
        private IAction _action;

        /// <summary>
        /// Initialize context bound action
        /// </summary>
        /// <param name="action"></param>
        public ContextBoundAction(IAction action)
        {
            if (action == null) {
                throw new ArgumentNullException("action");
            }
            _action = action;
        }
        /// <summary>
        /// Get action
        /// </summary>
        public IAction Action
        {
            get { return _action; }
        }
    }
}
