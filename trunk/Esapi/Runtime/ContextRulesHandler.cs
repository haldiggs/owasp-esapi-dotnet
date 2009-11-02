using System;
using System.Collections.Generic;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context rules handler
    /// </summary>
    internal class ContextRulesHandler : List<ContextBoundRule>, IContextHandler
    {
        #region IContextHandler Members
        /// <summary>
        /// Process context
        /// </summary>
        /// <param name="args">Current context</param>
        /// <returns>True if context handled, false otherwise</returns>
        public bool ProcessEvent(ContextEvent args)
        {
            if (args == null || string.IsNullOrEmpty(args.CurrentEvent)) {
                throw new ArgumentException();
            }

            foreach (ContextBoundRule boundRule in this) {
                // Not registered for this event
                if (!boundRule.Events.Contains(args.CurrentEvent)) {
                    continue;
                }

                // Run rule
                try {
                    boundRule.Rule.Process(new RuleArgs(args.CurrentEvent));
                }
                catch (Exception exp) {
                    // Log
                    Esapi.Logger.Error(LogEventTypes.FUNCTIONALITY, "Rule execution failed", exp);

                    // Run fault actions
                    ((IContextHandler)boundRule.FaultActions).ProcessEvent(args);
                }
            }

            return true;
        }

        #endregion
    }    
}
