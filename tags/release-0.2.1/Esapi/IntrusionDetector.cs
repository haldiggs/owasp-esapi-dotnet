using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.IntrusionDetection;
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
        
        public void Increment(int maxOccurences, TimeSpan maxTimeSpan)
        {
            DateTime now = DateTime.Now;
            _times.Add(now);

            while (_times.Count > maxOccurences)
                _times.RemoveAt(_times.Count - 1);

            if (_times.Count == maxOccurences) {
                if (now - _times[maxOccurences - 1] < maxTimeSpan) {
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
        public readonly string Event;

        /// <summary>
        /// The number of occurences.
        /// </summary>
        public readonly int MaxOccurences;

        /// <summary>
        /// The interval allowed between events.
        /// </summary>
        public readonly TimeSpan MaxTimeSpan;

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
        /// <param name="maxOccurences">
        /// Count of events allowed.
        /// </param>
        /// <param name="maxTimeSpan">
        /// Interval between events allowed.
        /// </param>
        /// <param name="actions">
        /// Actions associated with threshold.
        /// </param>
        public Threshold(string name, int maxOccurences, long maxTimeSpan, IEnumerable<string> actions)
        {
            Event           = name;
            MaxOccurences   = maxOccurences;
            MaxTimeSpan     = TimeSpan.FromSeconds(maxTimeSpan);

            Actions = new List<string>();
            
            // Add actions
            if (actions != null) {                
                foreach (string action in actions) {
                    string actionName = (action != null ? action.Trim() : action);
                    if (string.IsNullOrEmpty(actionName)) {
                        continue;
                    }

                    Actions.Add(actionName);
                }
            }
        }

        /// <summary>
        /// Returns string representation of threshold.
        /// </summary>
        /// <returns>String representation of threshold.</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("Threshold: {0} - {1} in {2} seconds results in ", Event, MaxOccurences, MaxTimeSpan);

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
        private Dictionary<string, Threshold>   _thresholds;
        private Dictionary<string, IAction>     _actions;
        
        /// <summary>
        /// Public constructor.
        /// </summary>
        public IntrusionDetector()
        {
            _thresholds = new Dictionary<string,Threshold>();
            _actions    = new Dictionary<string, IAction>();
            _logger     = Esapi.Logger;
        }

        /// <summary>
        /// Add action 
        /// </summary>
        /// <param name="name">Action unique name</param>
        /// <param name="action">Action instance</param>
        public void AddAction(string name, IAction action)
        {
            string actionName = (name != null ? name.Trim() : name);

            if (string.IsNullOrEmpty(actionName)) {
                throw new ArgumentException( EM.InstrusionDetector_InvalidActionName, "name");
            }
            if (action == null) {
                throw new ArgumentNullException("action");
            }
            if (_actions.ContainsKey(actionName)) {
                throw new ArgumentException(EM.IntrusionDetector_DuplicateActionName, "name");
            }

            _actions.Add(actionName, action);
        }

        /// <summary>
        /// Remove action
        /// </summary>
        /// <param name="name">Action name</param>
        /// <returns>True if succeeded, false otherwise</returns>
        public bool RemoveAction(string name)
        {
            if (!_actions.ContainsKey(name)) {
                return false;
            }

            // Make sure action is not referenced
            foreach (Threshold threshold in _thresholds.Values) {
                if (threshold.Actions.Contains(name)) {
                    string message = string.Format(EM.IntrusionDetector_ActionIsReferenced1, name);
                    throw new ArgumentException(message, "name");
                }
            }
            
            // Remove action
            return _actions.Remove(name);
        }

        /// <summary>
        /// Get action by name
        /// </summary>
        /// <param name="name">Action name</param>
        /// <rereturns>Action if found, null otherwise</rereturns>
        public IAction GetAction(string name)
        {
            IAction action;
            _actions.TryGetValue(name, out action);

            return action;
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
            if (_thresholds.ContainsKey(threshold.Event)) {
                throw new ArgumentException();
            }

            // Validate all required actions have been registered already
            if (threshold.Actions != null) {
                foreach (string name in threshold.Actions) {
                    if (!_actions.ContainsKey(name)) {
                        string message = string.Format(EM.IntrusionDetector_ActionNotFound1, name);
                        throw new ArgumentException(message, "threshold");
                    }
                }
            }

            // Add threshold
            _thresholds.Add(threshold.Event, threshold);
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
            if (e is EnterpriseSecurityException) {
                _logger.Warning(LogEventTypes.SECURITY, ((EnterpriseSecurityException)e).LogMessage, e);
            }
            else {                
                _logger.Warning(LogEventTypes.SECURITY, e.Message, e);
            }

            String eventName = e.GetType().FullName;

            if (e is IntrusionException) {
                return;
            }

            // add the exception to the user's store, handle IntrusionException if thrown
            try {
                AddSecurityEvent(eventName);
            }
            catch (IntrusionException) {
                OnIntrusionDetected(eventName);
            }
        }

        /// <summary> 
        /// Adds the event to the IntrusionDetector.
        /// </summary>
        /// <param name="eventName">The event to add.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IIntrusionDetector.AddEvent(string)">
        /// </seealso>
        public virtual void AddEvent(string eventName)
        {
            _logger.Warning(LogEventTypes.SECURITY, string.Format(EM.InstrusionDetector_EventReceived1, eventName));

            // add the event to the current user, which may trigger a detector 
            try {
                AddSecurityEvent(eventName);
            }
            catch (IntrusionException) {
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

            // Build action args
            IntrusionActionArgs args = new IntrusionActionArgs(quota);

            // Take actions
            foreach (string action in quota.Actions) {
                // Log action execution
                string message = string.Format(EM.InstrusionDetector_ExceededQuota4, quota.MaxOccurences, quota.MaxTimeSpan, eventName, action);                
                _logger.Fatal(LogEventTypes.SECURITY, "INTRUSION - " + message);
                                
                // Get action instance
                IAction actionInstance = null;
                if (!_actions.TryGetValue(action, out actionInstance)) {
                    message = string.Format(EM.IntrusionDetector_ActionNotFound1, action);
                    throw new EnterpriseSecurityException(message, message);
                }
                
                // Execute action
                // NOTE : we're not masking any action exceptions, they will be let to escape
                actionInstance.Execute(args);
            }
        }

        /// <summary> 
        /// Adds a security event to the user.        
        /// </summary>
        /// <param name="eventName">
        /// The security event to add.
        /// </param>
        private void AddSecurityEvent(string eventName)
        {
            IPrincipal currentUser = Esapi.SecurityConfiguration.CurrentUser;
            string username = (currentUser != null && currentUser.Identity != null ? currentUser.Identity.Name : "Anonymous");

            // Get user events
            Dictionary<string, Event> events;
            if (!users.TryGetValue(username, out events)) {
                events = new Dictionary<string, Event>();
                users[username] = events;
            }

            // Get user security event
            Event securityEvent;
            if (!events.TryGetValue(eventName, out securityEvent)) {
                securityEvent = new Event(eventName);
                events[eventName] = securityEvent;
            }

            Threshold q = GetEventThreshold(eventName);
            Debug.Assert(q != null);

            if (q.MaxOccurences > 0) {
                securityEvent.Increment(q.MaxOccurences, q.MaxTimeSpan);
            }

        }
    }
}
