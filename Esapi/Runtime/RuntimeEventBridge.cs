using System;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Base class to forward runtime events
    /// </summary>
    internal class RuntimeEventBridge : IRuntimeEventListener, IRuntimeEventPublisher
    {
        #region IRuntimeEventListener implementation
        /// <summary>
        /// Subscribe to publisher's events
        /// </summary>
        /// <param name="publisher"></param>
        public virtual void Subscribe(IRuntimeEventPublisher publisher)
        {
            publisher.PreRequestHandlerExecute += OnPreRequestHandlerExecute;
            publisher.PostRequestHandlerExecute += OnPostRequestHandlerExecute;
        }
        /// <summary>
        /// Disconnect from publisher's events
        /// </summary>
        /// <param name="publisher"></param>
        public virtual void Unsubscribe(IRuntimeEventPublisher publisher)
        {
            publisher.PreRequestHandlerExecute -= OnPreRequestHandlerExecute; ;
            publisher.PostRequestHandlerExecute -= OnPostRequestHandlerExecute;
        }
        #endregion

        #region IRuntimeEventPublisher implementation
        /// <summary>
        /// Before request handler is executed
        /// </summary>
        public event EventHandler<RuntimeEventArgs> PreRequestHandlerExecute;
        /// <summary>
        /// After request handler is executed
        /// </summary>
        public event EventHandler<RuntimeEventArgs> PostRequestHandlerExecute;

        #endregion

        #region Overridables
        /// <summary>
        /// Before event is forwarded template method
        /// </summary>
        /// <param name="handler">Handler to which the event is forwarded</param>
        /// <param name="sender">Who's sending the event</param>
        /// <param name="args">Arguments</param>
        /// <returns>True if event handled (not forwarded necessary), false otherwise</returns>
        /// <remarks>Override to prevent event forwarding</remarks>
        protected virtual bool BeforeForwardEvent(EventHandler<RuntimeEventArgs> handler, object sender, RuntimeEventArgs args)
        {
            return false;
        }
        /// <summary>
        /// After event is forwarded
        /// </summary>
        /// <param name="handler">Handler to which the event is forwarded</param>
        /// <param name="sender">Who's sending the event</param>
        /// <param name="args">Arguments</param>
        /// <returns></returns>
        /// <remarks>Override to be called after the event is forwarded</remarks>
        protected virtual bool AfterForwardEvent(EventHandler<RuntimeEventArgs> handler, object sender, RuntimeEventArgs args)
        {
            return false;
        }
        /// <summary>
        /// Event forward operation failed (exception thrown)
        /// </summary>
        /// <param name="handler">Handler to which the event is forwarded</param>
        /// <param name="sender">Who's sending the event</param>
        /// <param name="args">Arguments</param>
        /// <param name="exp">Exception thrown</param>
        /// <returns>True is fault handled, false otherwise</returns>
        /// <remarks>Override to process forward exceptions</remarks>
        protected virtual bool ForwardEventFault(EventHandler<RuntimeEventArgs> handler, object sender, RuntimeEventArgs args, Exception exp)
        {
            return false;
        }

        #endregion

        #region Event connectors
        /// <summary>
        /// Forward event
        /// </summary>
        /// <param name="handler"></param>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void ForwardEvent(EventHandler<RuntimeEventArgs> handler, object sender, RuntimeEventArgs args)
        {
            if (handler != null) {
                try {
                    if (BeforeForwardEvent(handler, sender, args)) {
                        return;
                    }

                    handler(sender, args);

                    if (AfterForwardEvent(handler, sender, args)) {
                        return;
                    }
                }
                catch (Exception exp) {
                    if (!ForwardEventFault(handler, sender, args, exp)) {
                        throw;
                    }
                }
            }
        }
        /// <summary>
        /// Bridge method - before handler exec
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void OnPreRequestHandlerExecute(object sender, RuntimeEventArgs args)
        {
            ForwardEvent(PreRequestHandlerExecute, sender, args);
        }
        /// <summary>
        /// Bridge method - after handler exec
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void OnPostRequestHandlerExecute(object sender, RuntimeEventArgs args)
        {
            ForwardEvent(PostRequestHandlerExecute, sender, args);
        }
        #endregion
    }
}
