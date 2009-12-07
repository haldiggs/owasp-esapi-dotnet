using System;
using System.Web;
using System.Collections.Generic;
using System.Diagnostics;
using Owasp.Esapi.Runtime.Conditions;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// ESAPI runtime module
    /// </summary>
    public class EsapiRuntimeModule : IHttpModule, IRuntimeEventPublisher
    {
        private EsapiRuntime _runtime;

        private object _handlersLock;
        private HashSet<Type> _handlerTypes;

        public EsapiRuntimeModule()
        {
            _runtime = new EsapiRuntime();

            _handlersLock = new object();
            _handlerTypes = new HashSet<Type>();
        }

        #region Public
        /// <summary>
        /// Get current module instance (if registered)
        /// </summary>
        public EsapiRuntimeModule Current
        {
            get
            {
                EsapiRuntimeModule instance = null;

                // Lookup module in the current running application
                HttpApplication currentApp = HttpContext.Current != null ?
                                                    HttpContext.Current.ApplicationInstance : 
                                                    null;
                if (currentApp != null) {
                    HttpModuleCollection modules = currentApp.Modules;

                    // Lookup first instance
                    foreach (String key in modules.Keys) {
                        if (null != (instance = (modules[key] as EsapiRuntimeModule))) {
                            break;
                        }
                    }
                }

                return instance;
            }
        }

        /// <summary>
        /// Get runtime instance
        /// </summary>
        public IRuntime RuntimeInstance
        {
            get { return _runtime; }
        }
        #endregion

        #region Context mapping 
        /// <summary>
        /// Mapp application to context
        /// </summary>
        /// <param name="applicationType"></param>
        private void MapApplicationContext(Type applicationType)
        {
            Debug.Assert(applicationType != null);

            object[] runRules = applicationType.GetCustomAttributes(typeof(RunRuleAttribute), true);
            if (runRules != null && runRules.Length > 0) {
                // Create new context
                IContext appContext = _runtime.CreateContext();
                appContext.BindCondition(new ValueBoundCondition(true), true);

                // Add rules to context
                foreach (RunRuleAttribute runRule in runRules) {
                    IContextRule rule = appContext.BindRule(ObjectBuilder.Build<IRule>(runRule.Rule));

                    // Add actions
                    if (runRule.FaultActions != null && runRule.FaultActions.Length > 0) {
                        foreach (Type action in runRule.FaultActions) {
                            rule.FaultActions.Add(ObjectBuilder.Build<IAction>(action));
                        }
                    }
                }
            }
        }
        /// <summary>
        /// Map handler to context
        /// </summary>
        /// <param name="handlerTpe"></param>
        private void MapHandlerContext(Type handlerType)
        {
            Debug.Assert(handlerType != null);

            object[] runRules = handlerType.GetCustomAttributes(typeof(RunRuleAttribute), true);
            if (runRules != null && runRules.Length > 0) {
                // Create new context
                IContext handlerContext = _runtime.CreateContext();
                handlerContext.BindCondition(new HandlerCondition(handlerType), true);

                // Add rules to context
                foreach (RunRuleAttribute runRule in runRules) {
                    IContextRule rule = handlerContext.BindRule(ObjectBuilder.Build<IRule>(runRule.Rule));

                    // Add actions
                    if (runRule.FaultActions != null && runRule.FaultActions.Length > 0) {
                        foreach (Type action in runRule.FaultActions) {
                            rule.FaultActions.Add(ObjectBuilder.Build<IAction>(action));
                        }
                    }
                }
            }
        }        
        #endregion

        #region IRuntimeEventPublisher Members

        public event EventHandler<RuntimeEventArgs> PreRequestHandlerExecute;
        public event EventHandler<RuntimeEventArgs> PostRequestHandlerExecute;

        #endregion

        #region IHttpModule Members

        /// <summary>
        /// Release runtime resources
        /// </summary>
        public void Dispose()
        {
            // Disconnect runtime
            _runtime.Unsubscribe(this);
        }

        /// <summary>
        /// Register for events
        /// </summary>
        /// <param name="context"></param>
        public void Init(HttpApplication context)
        {
            context.PostRequestHandlerExecute+= new EventHandler(OnPostRequestHandlerExecute);
            context.PreRequestHandlerExecute += new EventHandler(OnPreRequestHandlerExecute);
            context.PostMapRequestHandler += new EventHandler(OnPostMapRequestHandler);

            // Connect runtime
            _runtime.Subscribe(this);

            // Map application context
            MapApplicationContext(context.GetType());
        }
                
        #endregion
        /// <summary>
        /// Map request handler to context
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void OnPostMapRequestHandler(object sender, EventArgs e)
        {
            HttpContext context = ((HttpApplication)sender).Context;
            IHttpHandler handler = context.CurrentHandler;

            if (handler != null) {
                lock (_handlersLock) {
                    // Get code behind type
                    Type handlerType = handler.GetType();

                    // If handler not known map to context
                    if (!_handlerTypes.Contains(handlerType)) {
                        MapHandlerContext(handlerType);
                        _handlerTypes.Add(handlerType);
                    }
                }
            }
            
        }  
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void OnPreRequestHandlerExecute(object sender, EventArgs e)
        {
            if (PreRequestHandlerExecute != null) {
                PreRequestHandlerExecute(this, new RuntimeEventArgs());
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void OnPostRequestHandlerExecute(object sender, EventArgs e)
        {
            if (PostRequestHandlerExecute != null) {
                PostRequestHandlerExecute(this, new RuntimeEventArgs());
            }
        }
    }   
}
