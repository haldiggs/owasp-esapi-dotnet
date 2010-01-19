using System;
using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Runtime event arguments
    /// </summary>
    public class RuntimeEventArgs : EventArgs
    {
        /// <summary>
        /// Context stack
        /// </summary>
        private Stack<IContext> _contexts;

        private EvaluationCache<IContext, bool> _contextMatchCache;
        private EvaluationCache<ICondition, bool> _conditionEvalCache;

        /// <summary>
        /// Initialize runtime arguments
        /// </summary>
        public RuntimeEventArgs()
        {
            _contexts = new Stack<IContext>();
            _contextMatchCache = new EvaluationCache<IContext, bool>();
            _conditionEvalCache = new EvaluationCache<ICondition, bool>();            
        }
        /// <summary>
        /// Get context path
        /// </summary>
        public IEnumerable<IContext> ContextPath
        {
            get { return _contexts; }
        }
        /// <summary>
        /// Get current context
        /// </summary>
        public IContext CurrentContext
        {
            get { return (_contexts.Count > 0 ? _contexts.Peek() : null); }
        }

        #region Internal
        /// <summary>
        /// Push context
        /// </summary>
        /// <param name="context">
        /// A <see cref="IContext"/>
        /// </param>
        internal void PushContext(IContext context)
        {
            if (context == null) {
                throw new ArgumentNullException();
            }
            _contexts.Push(context);
        }
        /// <summary>
        /// Pop context
        /// </summary>
        /// <returns>
        /// A <see cref="IContext"/>
        /// </returns>
        internal IContext PopContext()
        {
            return _contexts.Pop();
        }
        /// <summary>
        /// Context match cache
        /// </summary>
        internal EvaluationCache<IContext, bool> MatchCache
        {
            get { return _contextMatchCache; }
        }
        /// <summary>
        /// Condition evaluation cache
        /// </summary>
        internal EvaluationCache<ICondition, bool> EvalCache
        {
            get { return _conditionEvalCache; }
        }

        #endregion
    }
}
