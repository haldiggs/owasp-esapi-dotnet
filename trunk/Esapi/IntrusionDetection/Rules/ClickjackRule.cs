using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Web;

namespace Owasp.Esapi.IntrusionDetection.Rules
{
    /// <summary>
    /// Clickjack detection rule
    /// </summary>
    public class ClickjackRule : IIntrusionOutputRule
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

        #region IIntrusionOutputRule Members

        /// <summary>
        /// Insert clickjack prevention
        /// </summary>
        /// <param name="args"></param>
        public void Process(IntrusionOutputRuleArgs args)
        {
            if (args == null) {
                throw new ArgumentNullException("args");
            }
            
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

        #endregion
    }
}
