using System;
using System.Collections.Generic;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context bound conditions
    /// </summary>
    internal class ContextConditionsHandler : List<ContextBoundCondition>, IContextHandler
    {
        #region IContextHandler Members
        /// <summary>
        /// Process context
        /// </summary>
        /// <param name="args">Current context</param>
        /// <returns>True if context matches all conditions, false otherwise</returns>
        public bool ProcessEvent(ContextEvent args)
        {
            if (args == null || args.ConditionValueCache == null) {
                throw new ArgumentException();
            }

            bool result = (Count == 0 ? false : true);

            foreach (ContextBoundCondition boundCondition in this) {
                // Get cached result
                bool value = false;
                if (!args.ConditionValueCache.TryGetValue(boundCondition.Condition, out value)) {
                    // Evaluate & cache
                    value = (boundCondition.Condition.Evaluate(ConditionArgs.Empty) == boundCondition.Result);
                    args.ConditionValueCache.SetValue(boundCondition.Condition, value);
                }

                // Set result
                result &= value;
                if (!result) {
                    break;
                }
            }

            return result;
        }

        #endregion
    }
}
