using Owasp.Esapi.Interfaces;
using System;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Runtime implementation
    /// </summary>
    public class EsapiRuntime
    {
        /// <summary>
        /// Singleton intance
        /// </summary>
        private static EsapiRuntime s_Instance;

        private NamedObjectRepository<IAction> _actions;
        private NamedObjectRepository<ICondition> _conditions;
        private NamedObjectRepository<IRule> _rules;
        private NamedObjectRepository<Context> _contexts;

        /// <summary>
        /// Initialize runtime
        /// </summary>
        static EsapiRuntime()
        {
            s_Instance = new EsapiRuntime();
        }

        /// <summary>
        /// Reset instance
        /// </summary>
        internal static void Reset()
        {
            s_Instance = new EsapiRuntime();
        }

        /// <summary>
        /// Initialize runtime
        /// </summary>
        internal EsapiRuntime()
        {
            _actions = new NamedObjectRepository<IAction>();
            _contexts = new NamedObjectRepository<Context>();
            _rules = new NamedObjectRepository<IRule>();
            _conditions = new NamedObjectRepository<ICondition>();
        }

        /// <summary>
        /// Get current runtime 
        /// </summary>
        public static EsapiRuntime Current
        {
            get { return s_Instance; }
        }


        #region IRuntime Members
        /// <summary>
        /// Get actions
        /// </summary>
        public IObjectRepository<string, IAction> Actions
        {
            get { return _actions; }
        }
        /// <summary>
        /// Get conditions
        /// </summary>
        public IObjectRepository<string, ICondition> Conditions
        {
            get { return _conditions; }
        }
        /// <summary>
        /// Get rules
        /// </summary>
        public IObjectRepository<string, IRule> Rules
        {
            get { return _rules; }
        }
        /// <summary>
        /// Get contexts
        /// </summary>
        public IObjectRepository<string, Context> Contexts
        {
            get { return _contexts; }
        }

        #endregion
        /// <summary>
        /// Register context
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public Context RegisterContext(string name)
        {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("Invalid name", "name");
            }

            Context prevContext = null;
            if (_contexts.Lookup(name, out prevContext)) {
                throw new ArgumentException("Duplicate name", "name");
            }

            Context context = new Context(name);
            _contexts.Register(name, context);
            return context;
        }
    }
}
