using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Web.Security;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi
{
    /// <summary>
    /// Security event
    /// </summary>
    internal class Event
    {
        private string          _key;
        private List<DateTime>  _times;

        public Event(string key)
        {
            this._key = key;
            _times =  new List<DateTime>();
        }
        
        public void Increment(int count, long interval)
        {
            DateTime now = DateTime.Now;
            _times.Add(now);

            while (_times.Count > count)
                _times.RemoveAt(_times.Count - 1);

            if (_times.Count == count)
            {
                DateTime past = (DateTime)_times[count - 1];
                long plong = past.Ticks;
                long nlong = now.Ticks;
                if (nlong - plong < interval * 60 * 10000 * 1000)
                {
                    throw new IntrusionException(EM.IntrusionDetector_ThresholdExceeded, string.Format(EM.InstrusionDetector_ThresholdExceeded1, _key));
                }
            }
        }
    }

    /// <summary>
    /// The Threshold class is used to represent the amount of events that can be allowed, and in
    /// what timeframe they are allowed.
    /// </summary>
    public class Threshold
    {
        /// <summary>
        /// The name of the event.
        /// </summary>
        public readonly string Name;

        /// <summary>
        /// The number of occurences.
        /// </summary>
        public readonly int Count;

        /// <summary>
        /// The interval allowed between events.
        /// </summary>
        public readonly long Interval;

        /// <summary>
        /// The list of actions associated with the threshold/
        /// </summary>
        public readonly IList<string> Actions;

        /// <summary>
        /// Constructor for Threshold
        /// </summary>
        /// <param name="name">
        /// Event name.
        /// </param>
        /// <param name="count">
        /// Count of events allowed.
        /// </param>
        /// <param name="interval">
        /// Interval between events allowed.
        /// </param>
        /// <param name="actions">
        /// Actions associated with threshold.
        /// </param>
        public Threshold(string name, int count, long interval, IEnumerable<string> actions)
        {
            Name     = name;
            Count    = count;
            Interval = interval;
            Actions  = actions != null ? new List<string>(actions) : new List<string>();
        }

        /// <summary>
        /// Returns string representation of threshold.
        /// </summary>
        /// <returns>String representation of threshold.</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("Threshold: {0} - {1} in {2} seconds results in ", Name, Count, Interval);

            for (int i = 0; i < Actions.Count; ++i) {
                if (i != 0) {
                    sb.Append(", ");
                }
                sb.AppendFormat(Actions[i]);
            }

            return sb.ToString();
        }
    }


    /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IIntrusionDetector"/>
    /// <summary> Reference implementation of the <see cref="Owasp.Esapi.Interfaces.IIntrusionDetector"/> interface. 
    /// </summary>
    /// <remarks>
    /// This implementation monitors EnterpriseSecurityExceptions to see if any user
    /// exceeds a configurable threshold in a configurable time period. For example,
    /// it can monitor to see if a user exceeds 10 input validation issues in a 1
    /// minute period. Or if there are more than 3 authentication problems in a 10
    /// second period. More complex implementations are certainly possible, such as
    /// one that establishes a baseline of expected behavior, and then detects
    /// deviations from that baseline.
    /// </remarks>
    public class IntrusionDetector : IIntrusionDetector
    {        
        private static Dictionary<string, Dictionary<string, Event>> users = new Dictionary<string, Dictionary<string, Event>>();

        /// <summary>The logger. </summary>
        private readonly ILogger _logger;        
        private Dictionary<string, Threshold> _thresholds;
        
        /// <summary>
        /// Public constructor.
        /// </summary>
        public IntrusionDetector()
        {
            _thresholds = new Dictionary<string,Threshold>();
            _logger     = Esapi.Logger;
        }

        /// <summary>
        /// Add event threshold
        /// </summary>
        /// <param name="threshold"></param>
        public void AddThreshold(Threshold threshold)
        {
            if (threshold == null) {
                throw new ArgumentNullException("threshold");
            }
            if (_thresholds.ContainsKey(threshold.Name)) {
                throw new ArgumentException();
            }

            _thresholds.Add(threshold.Name, threshold);
        }

        /// <summary>
        /// Remove event threshold
        /// </summary>
        /// <param name="eventName"></param>
        /// <returns></returns>
        public bool RemoveThreshold(string eventName)
        {
            return _thresholds.Remove(eventName);
        }

        /// <summary>
        /// Get event threshold
        /// </summary>
        /// <param name="eventName"></param>
        /// <returns></returns>
        private Threshold GetEventThreshold(string eventName)
        {
            Threshold threshold;
            _thresholds.TryGetValue(eventName, out threshold);

            // Event not found, create default
            if (threshold == null) {
                threshold = new Threshold(eventName, 0, 0, null);
            }

            return threshold;
        }

        // FIXME: ENHANCE consider allowing both per-user and per-application quotas
        // e.g. number of failed logins per hour is a per-application quota

        /// <summary> This implementation uses an exception store in each User object to track
        /// exceptions.        
        /// </summary>
        /// <param name="e">The exception to add.        
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IIntrusionDetector.AddException(Exception)">
        /// </seealso>
        public void AddException(Exception e)
        {
            if (e is EnterpriseSecurityException)
            {
                _logger.Warning(LogEventTypes.SECURITY, ((EnterpriseSecurityException)e).LogMessage, e);
            }
            else
            {                
                _logger.Warning(LogEventTypes.SECURITY, e.Message, e);
            }

            String eventName = e.GetType().FullName;

            if (e is IntrusionException)
            {
                return;
            }

            // add the exception to the user's store, handle IntrusionException if thrown
            try
            {
                AddSecurityEvent(eventName);
            }
            catch (IntrusionException)
            {
                OnIntrusionDetected(eventName);
            }
        }

        /// <summary> Adds the event to the IntrusionDetector.
        /// 
        /// </summary>
        /// <param name="eventName">The event to add.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IIntrusionDetector.AddEvent(string)">
        /// </seealso>
        public virtual void AddEvent(string eventName)
        {
            _logger.Warning(LogEventTypes.SECURITY, string.Format(EM.InstrusionDetector_EventReceived1, eventName));

            // add the event to the current user, which may trigger a detector 
            try
            {
                AddSecurityEvent(eventName);
            }
            catch (IntrusionException)
            {
                OnIntrusionDetected(eventName);
            }
        }

        /// <summary>
        /// Instrusion was detected
        /// </summary>
        /// <param name="eventName"></param>
        private void OnIntrusionDetected(string eventName)
        {
            Threshold quota = GetEventThreshold(eventName);
            if (quota == null) {
                throw new ArgumentException(EM.IntrusionDetector_UnknownEventName, "eventName");
            }

            // Take action
            foreach (string action in quota.Actions) {
                string message = string.Format(EM.InstrusionDetector_ExceededQuota4, quota.Count, quota.Interval, eventName, action);
                TakeSecurityAction(action, message);
            }
        }

        /// <summary>
        /// This method performs a security action based on an intrustion threshold.
        /// </summary>
        /// <param name="action">The action to take.</param>
        /// <param name="message">The message to log regarding the action.</param>
        private void TakeSecurityAction(string action, string message)
        {
            // TODO : 
            // - accept configurable security actions a la "Codec" and "Validation Rule"
            // - remove hardcoded actions
            if (action.Equals("log"))
            {
                _logger.Fatal(LogEventTypes.SECURITY, "INTRUSION - " + message);
            }
            if (Membership.GetUser() != null)
            {
                if (action.Equals("disable"))
                {
                    Membership.GetUser().IsApproved = false;
                }
                if (action.Equals("logout"))
                {
                    FormsAuthentication.SignOut();
                }
            }
        }

        /// <summary> 
        /// Adds a security event to the user.        
        /// </summary>
        /// <param name="eventName">
        /// The security event to add.
        /// </param>
        public void AddSecurityEvent(string eventName)
        {            
            string username = (Membership.GetUser() == null) ? "Anonymous" : Membership.GetUser().UserName;

            Dictionary<string, Event> events;

            if (!users.TryGetValue(username, out events)) {
                events = new Dictionary<string, Event>();
                users[username] = events;
            }

            Event securityEvent;

            if (!events.TryGetValue(eventName, out securityEvent)) {
                securityEvent = new Event(eventName);
                events[eventName] = securityEvent;
            }

            Threshold q = GetEventThreshold(eventName);
            Debug.Assert(q != null);

            if (q.Count > 0) {
                securityEvent.Increment(q.Count, q.Interval);
            }

        }
    }
}
