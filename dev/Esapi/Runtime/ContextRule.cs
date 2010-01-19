using System;
using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context rule implementation
    /// </summary>
    internal class ContextRule : RuntimeEventBridge, IContextRule, IDisposable
    {
        private IRule _rule;
        private List<IAction> _faultActions;

        /// <summary>
        /// Initialize context rule
        /// </summary>
        /// <param name="rule">
        /// A <see cref="IRule"/>
        /// </param>
        internal ContextRule(IRule rule)
        {
            if (rule == null) {
                throw new ArgumentNullException();
            }
            _rule = rule;
            _faultActions = new List<IAction>();

            // Subscribe rule to events
            _rule.Subscribe(this);
        }
        /// <summary>
        /// Unsubscribe from publisher's events
        /// </summary>
        /// <param name="publisher">
        /// A <see cref="IRuntimeEventPublisher"/>
        /// </param>
        public override void Unsubscribe(IRuntimeEventPublisher publisher)
        {
            base.Unsubscribe(publisher);
            _rule.Unsubscribe(this);
        }
        /// <summary>
        /// Handle rule execution fault
        /// </summary>
        /// <param name="handler">
        /// A <see cref="EventHandler<RuntimeEventArgs>"/>
        /// </param>
        /// <param name="sender">
        /// A <see cref="System.Object"/>
        /// </param>
        /// <param name="args">
        /// A <see cref="RuntimeEventArgs"/>
        /// </param>
        /// <param name="exp">
        /// A <see cref="Exception"/>
        /// </param>
        /// <returns>
        /// A <see cref="System.Boolean"/>
        /// </returns>
        protected override bool ForwardEventFault(EventHandler<RuntimeEventArgs> handler, object sender, RuntimeEventArgs args, Exception exp)
        {
            // Init action args
            ActionArgs actionArgs = new ActionArgs() {
                FaultingRule = _rule,
                FaultException = exp,
                RuntimeArgs = args
            };

            try {
                // Run each action
                foreach (IAction action in _faultActions) {
                    action.Execute(actionArgs);
                }
            }
            catch (Exception) {
                // Nothing to do anymore, throw 
                throw;
            }

            return true;
        }



        #region IContextRule implementation
        public IRule Rule
        {
            get
            {
                return _rule;
            }
        }

        public ICollection<IAction> FaultActions
        {
            get
            {
                return _faultActions;
            }
        }
        #endregion

        #region IDisposable implementation
        public void Dispose()
        {
            _rule.Unsubscribe(this);
        }
        #endregion
    }
}
