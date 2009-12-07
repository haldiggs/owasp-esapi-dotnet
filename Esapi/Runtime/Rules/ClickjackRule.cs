using System;
using System.Web;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Runtime;

namespace Owasp.Esapi.Runtime.Rules
{
    /// <summary>
    /// Clickjack detection rule
    /// </summary>
    public class ClickjackRule : IRule
    {
        /// <summary>
        /// Framing mode
        /// </summary>
        public enum FramingModeType
        {
            /// <summary>
            /// Deny framing
            /// </summary>
            Deny,
            /// <summary>
            /// Allow only same domain
            /// </summary>
            Sameorigin
        }

        private const string HeaderName      = "X-FRAME-OPTIONS";
        private const string DenyValue       = "DENY";
        private const string SameoriginValue = "SAMEORIGIN";

        private FramingModeType _mode;

        /// <summary>
        /// Framing mode type
        /// </summary>
        public FramingModeType FramingMode
        {
            get { return _mode;  }
            set { _mode = value; }
        }

        /// <summary>
        /// Initialize clickjack rule
        /// </summary>
        public ClickjackRule()
        {
            _mode = FramingModeType.Deny;
        }

        /// <summary>
        /// Initialize clickjack rule
        /// </summary>
        /// <param name="mode">Framing mode type</param>
        public ClickjackRule(FramingModeType mode)
        {
            _mode = mode;
        }

        #region IRule Members
        /// <summary>
        /// Subscribe to events
        /// </summary>
        /// <param name="publisher"></param>
        public void Subscribe(IRuntimeEventPublisher publisher)
        {
            if (publisher == null) {
                throw new ArgumentNullException();
            }
            publisher.PostRequestHandlerExecute += OnPostRequestHandlerExecute;
        }
        /// <summary>
        /// Disconnect from events
        /// </summary>
        /// <param name="publisher"></param>
        public void Unsubscribe(IRuntimeEventPublisher publisher)
        {
            if (publisher == null) {
                throw new ArgumentNullException();
            }
            publisher.PostRequestHandlerExecute -= OnPostRequestHandlerExecute;
        }

        #endregion
        /// <summary>
        /// Add clickjack headers
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void OnPostRequestHandlerExecute(object sender, RuntimeEventArgs e)
        {
            // Get response
            HttpResponse response = (HttpContext.Current != null ? HttpContext.Current.Response : null);
            if (response == null) {
                throw new InvalidOperationException();
            }

            // Add clickjack protection
            switch (_mode) {
                case FramingModeType.Deny:
                    response.AddHeader(HeaderName, DenyValue);
                    break;
                case FramingModeType.Sameorigin:
                    response.AddHeader(HeaderName, SameoriginValue);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }
}
