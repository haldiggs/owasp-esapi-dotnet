using System;
using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context handler
    /// </summary>
    internal class ContextCollectionHandler : List<Context>, IContextHandler
    {
        /// <summary>
        /// Check if contains context by name
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        internal bool Contains(string name)
        {
            foreach (Context c in this) {
                if (string.Compare(c.Name, name) == 0) {
                    return true;
                }
            }
            return false;
        }
        #region IContextHandler Members
        /// <summary>
        /// Process context
        /// </summary>
        /// <param name="args"></param>
        /// <returns>True if handled, false otherwise</returns>
        public bool ProcessEvent(ContextEvent args)
        {
            if (args == null || string.IsNullOrEmpty(args.CurrentEvent)) {
                throw new ArgumentException();
            }

            foreach (Context context in this) {
                ((IContextHandler)context).ProcessEvent(args);
            }

            return true;
        }

        #endregion
    }
}
