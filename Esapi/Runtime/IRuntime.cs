using System;
using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Runtime interface
    /// </summary>
    public interface IRuntime
    {
        /// <summary>
        /// Runtime named rules
        /// </summary>
        IObjectRepository<string, IRule> Rules { get; }
        /// <summary>
        /// Runtime named conditions
        /// </summary>
        IObjectRepository<string, ICondition> Conditions { get; }
        /// <summary>
        /// Runtime named actions
        /// </summary>
        IObjectRepository<string, IAction> Actions { get; }
        /// <summary>
        /// Context hierarchy
        /// </summary>
        ICollection<IContext> Contexts { get; }
        /// <summary>
        /// Create context
        /// </summary>
        /// <returns></returns>
        /// <remarks>Name is automatically generated</remarks>
        IContext CreateContext();
        /// <summary>
        /// Create named context
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        IContext CreateContext(string name);
        /// <summary>
        /// Lookup context by name
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        IContext LookupContext(string name);
        /// <summary>
        /// Register context
        /// </summary>
        /// <param name="name"></param>
        /// <param name="context"></param>
        void RegisterContext(string name, IContext context);
        /// <summary>
        /// Remove context
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        IContext RemoveContext(string name);
    }

    /// <summary>
    /// Runtime event publisher
    /// </summary>
    public interface IRuntimeEventPublisher
    {
        /// <summary>
        /// Before request handler execution
        /// </summary>
        event EventHandler<RuntimeEventArgs> PreRequestHandlerExecute;
        /// <summary>
        /// After request handler execution
        /// </summary>
        event EventHandler<RuntimeEventArgs> PostRequestHandlerExecute;
    }

    /// <summary>
    /// Runtime event listener interface
    /// </summary>
    public interface IRuntimeEventListener
    {
        /// <summary>
        /// Subscribe to publisher's events
        /// </summary>
        /// <param name="publisher"></param>
        void Subscribe(IRuntimeEventPublisher publisher);
        /// <summary>
        /// Disconnect from publisher's events
        /// </summary>
        /// <param name="publisher"></param>
        void Unsubscribe(IRuntimeEventPublisher publisher);
    }
}
