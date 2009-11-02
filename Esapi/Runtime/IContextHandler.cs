using System;
using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context handler interface
    /// </summary>
    internal interface IContextHandler
    {
        /// <summary>
        /// Process context event
        /// </summary>
        /// <param name="args">Current context</param>
        /// <returns>True if context handled, false otherwise</returns>
        bool ProcessEvent(ContextEvent args);
    }
}
