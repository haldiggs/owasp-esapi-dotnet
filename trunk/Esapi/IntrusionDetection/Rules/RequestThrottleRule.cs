using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web;
using System.Web.SessionState;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi.IntrusionDetection.Rules
{
    /// <summary>
    /// Throttle requests rule
    /// </summary>
    public class RequestThrottleRule : IRule
    {
        private const string SessionKey = "Owasp.Esapi.IntrusionDetection.Rules.RequestThrottleRule";

        private int         _maxCount;
        private TimeSpan    _timespan;

        /// <summary>
        /// Initialize request throttle rule
        /// </summary>
        public RequestThrottleRule()
        {
            _maxCount = 5;
            _timespan = new TimeSpan(0, 0, 10);
        }

        /// <summary>
        /// Initialize request throttle rule
        /// </summary>
        /// <param name="maxCount">Maximum hit count</param>
        /// <param name="timeSpan">Time interval (in seconds)</param>
        public RequestThrottleRule(int maxCount, int timeSpan)
        {
            if (maxCount <= 0) {
                throw new ArgumentOutOfRangeException("maxCount");
            }
            if (timeSpan <= 0) {
                throw new ArgumentOutOfRangeException("timeSpan");
            }
        }

        /// <summary>
        /// Maximum hit count
        /// </summary>
        public int MaxCount
        {
            get { return _maxCount; }
            set
            {
                if (value < 0) {
                    throw new ArgumentException();
                }
                _maxCount = value;
            }
        }

        /// <summary>
        /// Time interval
        /// </summary>
        public int TimeSpan
        {
            get { return _timespan.Seconds; }
            set
            {
                if (value <= 0) {
                    throw new ArgumentException();
                }
                _timespan = new TimeSpan(0, 0, value);
            }
        }

        /// <summary>
        /// Get request history
        /// </summary>
        /// <returns>Request history</returns>
        private List<DateTime> GetRequestHistory()
        {
            HttpSessionState session = (HttpContext.Current != null ? HttpContext.Current.Session : null);
            if (session == null) {
                throw new EnterpriseSecurityException(EM.RequestThrottleRule_SessionRequired, EM.RequestThrottleRule_SessionRequired);
            }

            List<DateTime> history = session[SessionKey] as List<DateTime>;
            if (history == null) {
                history = new List<DateTime>();
                session[SessionKey] = history;
            }

            return history;
        }

        #region IRule Members

        /// <summary>
        /// Verify request rate
        /// </summary>
        /// <param name="args"></param>
        public void Process(RuleArgs args)
        {
            if (args == null) {
                throw new ArgumentNullException("args");
            }

            // Verify request stage
            IntrusionRuleArgs intrusionArgs = (IntrusionRuleArgs)args;
            if (intrusionArgs.Stage != RequestStage.PreRequestHandlerExecute) {
                return;
            }
            
            // Get current and history requests
            List<DateTime> requestHistory = GetRequestHistory();
            Debug.Assert(requestHistory != null);

            DateTime currentTimestamp = DateTime.Now;

            // Lookup first in timespan
            int pos = -1;
            for (int i = 0; i < requestHistory.Count; ++i) {
                DateTime hit = requestHistory[i];
                if (currentTimestamp - hit <= _timespan) {
                    pos = i;
                    break;
                }
            }

            // Add current
            requestHistory.Add(currentTimestamp);

            // Check & cleanup
            if (pos != -1) {
                // Remove expired records
                for (int i = 0; i < pos; ++i) {
                    requestHistory.RemoveAt(0);
                }
                // Check interval
                if (requestHistory.Count >= _maxCount) {
                    throw new IntrusionException(EM.RequestThrottleRule_MaximumExceeded, EM.RequestThrottleRule_MaximumExceeded);
                }
            }
        }

        #endregion
    }
}
