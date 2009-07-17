using System;
using System.Collections;
using System.Web.Security;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    class Event
    {
        public string key;
        public ArrayList times = new ArrayList();
        public long count = 0;

        public Event(string key)
        {
            this.key = key;
        }
        
        public void Increment(int count, long interval)
        {
            DateTime now = DateTime.Now;
            times.Insert(0, now);
            while (times.Count > count)
                times.RemoveAt(times.Count - 1);
            if (times.Count == count)
            {
                DateTime past = (DateTime)times[count - 1];
                long plong = past.Ticks;
                long nlong = now.Ticks;
                long l = nlong - plong;
                long i = interval * 10000 * 1000;
                if (nlong - plong < interval * 60 * 10000 * 1000)
                {
                    throw new IntrusionException("Threshold exceeded", "Exceeded threshold for " + key);
                }
            }
        }
    }


    public class Threshold
    {
        /// <summary>
        /// The name of the event.
        /// </summary>
        public string Name = null;

        /// <summary>
        /// The number of occurences.
        /// </summary>
        public int Count = 0;

        /// <summary>
        /// The interval allowed between events.
        /// </summary>
        public long Interval = 0;

        /// <summary>
        /// The list of actions associated with the threshold/
        /// </summary>
        public IList Actions = null;

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
        public Threshold(string name, int count, long interval, IList actions)
        {
            this.Name = name;
            this.Count = count;
            this.Interval = interval;
            this.Actions = actions;
        }

        /// <summary>
        /// Returns string representation of threshold.
        /// </summary>
        /// <returns>String representation of threshold.</returns>
        public override string ToString()
        {
            return "Threshold: " + Name + " - " + Count + " in " + Interval + " seconds results in " + Actions.ToString();
        }
    }

    /// <summary> Reference implementation of the IIntrusionDetector interface. This
    /// implementation monitors EnterpriseSecurityExceptions to see if any user
    /// exceeds a configurable threshold in a configurable time period. For example,
    /// it can monitor to see if a user exceeds 10 input validation issues in a 1
    /// minute period. Or if there are more than 3 authentication problems in a 10
    /// second period. More complex implementations are certainly possible, such as
    /// one that establishes a baseline of expected behavior, and then detects
    /// deviations from that baseline.
    /// 
    /// </summary>
    /// <seealso cref="Owasp.Esapi.Interfaces.IIntrusionDetector">
    /// </seealso>
    public class IntrusionDetector : IIntrusionDetector
    {        
        /// <summary>The logger. </summary>
        private static readonly ILogger logger;
        private static Hashtable users = new Hashtable();
        
        /// <summary>
        /// Public constructor.
        /// </summary>
        public IntrusionDetector()
        {
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
                logger.Warning(LogEventTypes.SECURITY, ((EnterpriseSecurityException)e).LogMessage, e);
            }
            else
            {                
                logger.Warning(LogEventTypes.SECURITY, e.Message, e);
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
                Threshold quota = Esapi.SecurityConfiguration.GetQuota(eventName);
                IEnumerator i = quota.Actions.GetEnumerator();                
                while (i.MoveNext())
                {                    
                    string action = (string)i.Current;
                    string message = "User exceeded quota of " + quota.Count + " per " + quota.Interval + " seconds for event " + eventName + ". Taking actions " + quota.Actions.ToString();
                    TakeSecurityAction(action, message);
                }
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
            logger.Warning(LogEventTypes.SECURITY, "Security event " + eventName + " received");

            // add the event to the current user, which may trigger a detector 
            try
            {
                AddSecurityEvent("event." + eventName);
            }
            catch (IntrusionException)
            {
                Threshold quota = Esapi.SecurityConfiguration.GetQuota("event." + eventName);
                IEnumerator i = quota.Actions.GetEnumerator();                
                while (i.MoveNext())
                {                    
                    string action = (string)i.Current;
                    string message = "User exceeded quota of " + quota.Count + " per " + quota.Interval + " seconds for event " + eventName + ". Taking actions " + quota.Actions.ToString();
                    TakeSecurityAction(action, message);
                }
            }
        }

        /// <summary>
        /// This method performs a security action based on an intrustion threshold.
        /// </summary>
        /// <param name="action">The action to take.</param>
        /// <param name="message">The message to log regarding the action.</param>
        private void TakeSecurityAction(string action, string message)
        {
            if (action.Equals("log"))
            {
                logger.Fatal(LogEventTypes.SECURITY, "INTRUSION - " + message);
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
            Hashtable events = (Hashtable)users[username];
            if (events == null)
            {
                events = new Hashtable();
                users[username] = events;
            }
            Event securityEvent = (Event)events[eventName];
            if (securityEvent == null)
            {
                securityEvent = new Event(eventName);
                events[eventName] = securityEvent;
            }

            Threshold q = Esapi.SecurityConfiguration.GetQuota(eventName);
            
            if (q.Count > 0)
            {
                securityEvent.Increment(q.Count, q.Interval);
            }

        }

        /// <summary>
        ///  Static constructor.
        /// </summary>
        static IntrusionDetector()
        {
            logger = Esapi.Logger;
        }
    }
}
