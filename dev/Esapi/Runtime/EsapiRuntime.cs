using System;
using System.Collections.Generic;
using System.Threading;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// ESAPI Runtime implementation
    /// </summary>
    internal class EsapiRuntime : RuntimeEventBridge, IRuntime, IDisposable
    {
        private NamedObjectRepository<IAction> _actions;
        private NamedObjectRepository<IRule> _rules;
        private NamedObjectRepository<ICondition> _conditions;

        private ReaderWriterLockSlim _contextsLock;
        private NamedObjectRepository<IContext> _contexts;

        /// <summary>
        /// Initialize runtime instance
        /// </summary>
        public EsapiRuntime()
        {
            _actions = new NamedObjectRepository<IAction>();
            _rules = new NamedObjectRepository<IRule>();
            _conditions = new NamedObjectRepository<ICondition>();

            _contextsLock = new ReaderWriterLockSlim();
            _contexts = new NamedObjectRepository<IContext>();
        }
        /// <summary>
        /// Disconnect from publisher's events
        /// </summary>
        /// <param name="publisher"></param>
        public override void Unsubscribe(IRuntimeEventPublisher publisher)
        {
            base.Unsubscribe(publisher);

            _contextsLock.EnterReadLock();

            try {
                foreach (IContext context in _contexts.Objects) {
                    IRuntimeEventListener rteListener = context as IRuntimeEventListener;
                    if (rteListener != null) {
                        rteListener.Unsubscribe(this);
                    }
                }
            }
            finally {
                _contextsLock.ExitReadLock();
            }
        }
        #region IEsapiRuntime implementation        
        /// <summary>
        /// Runtime registered actions
        /// </summary>
        public IObjectRepository<string, IAction> Actions
        {
            get { return _actions; }
        }
        /// <summary>
        /// Runtime registered rules
        /// </summary>
        public IObjectRepository<string, IRule> Rules
        {
            get { return _rules; }
        }
        /// <summary>
        /// Runtime registered conditions
        /// </summary>
        public IObjectRepository<string, ICondition> Conditions
        {
            get { return _conditions; }
        }
        /// <summary>
        /// Context hierarchy
        /// </summary>
        public ICollection<IContext> Contexts
        {
            get { return _contexts.Objects; }
        }
        /// <summary>
        /// Register new context
        /// </summary>
        /// <returns></returns>
        /// <remarks>Context name is automatically generated</remarks>
        public IContext CreateContext()
        {
            return CreateContext(Guid.NewGuid().ToString());
        }
        /// <summary>
        /// Register named context
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public IContext CreateContext(string name)
        {
            _contextsLock.EnterWriteLock();

            try {
                IContext prevContext;
                if (_contexts.Lookup(name, out prevContext)) {
                    throw new ArgumentException();
                }

                Context context = new Context(name);
                context.Subscribe(this);

                _contexts.Register(name, context);
                return context;
            }
            finally {
                _contextsLock.ExitWriteLock();
            }
        }
        /// <summary>
        /// Lookup context by name
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public IContext LookupContext(string name)
        {
            _contextsLock.EnterReadLock();

            try {
                IContext context;
                _contexts.Lookup(name, out context);
                return context;
            }
            finally {
                _contextsLock.ExitReadLock();
            }
        }
        /// <summary>
        /// Register context
        /// </summary>
        /// <param name="name"></param>
        /// <param name="context"></param>
        public void RegisterContext(string name, IContext context)
        {
            _contextsLock.EnterWriteLock();

            try {
                IContext prevContext;
                if (_contexts.Lookup(name, out prevContext)) {
                    throw new ArgumentException();
                }

                if (context is IRuntimeEventListener) {
                    ((IRuntimeEventListener)context).Subscribe(this);
                }
                _contexts.Register(name, context);
            }
            finally {
                _contextsLock.ExitWriteLock();
            }
        }
        /// <summary>
        /// Remove context
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public IContext RemoveContext(string name)
        {
            _contextsLock.EnterWriteLock();

            try {
                IContext context;
                if (_contexts.Lookup(name, out context)) {
                    _contexts.Revoke(name);
                }
                return context;
            }
            finally {
                _contextsLock.ExitWriteLock();
            }
        }
        #endregion

        #region IDisposable implementation
        /// <summary>
        /// Release contexts
        /// </summary>
        public void Dispose()
        {
            _contextsLock.EnterReadLock();

            try {
                foreach (IContext context in _contexts.Objects) {
                    IDisposable ctxDispose = context as IDisposable;
                    if (ctxDispose != null) {
                        ctxDispose.Dispose();
                    }
                }
            }
            finally {
                _contextsLock.ExitReadLock();
            }
        }
        #endregion
    }
}
