using System;
using System.Collections.Generic;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context action handler
    /// </summary>
    internal class ContextActionsHandler : List<ContextBoundAction>, IContextHandler
    {
        #region IContextHandler Members
        /// <summary>
        /// Process context event
        /// </summary>
        /// <param name="args"></param>
        /// <returns>True</returns>
        public bool ProcessEvent(ContextEvent args)
        {
            if (args == null || string.IsNullOrEmpty(args.CurrentEvent)) {
                throw new ArgumentException();
            }

            ActionArgs actionArgs = new ActionArgs(args.CurrentEvent);

            int index = 0;
            foreach (ContextBoundAction boundAction in this) {
                try {
                    boundAction.Action.Execute(actionArgs);
                    ++index;
                }
                catch (Exception fexp) {
                    Esapi.Logger.Error(LogEventTypes.FUNCTIONALITY, "Action execution failed", fexp);
                    throw;
                }
            }

            return true;
        }

        #endregion
    }
}
