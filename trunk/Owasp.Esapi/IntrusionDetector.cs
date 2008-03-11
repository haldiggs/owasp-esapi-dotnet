/// <summary> OWASP Enterprise Security API .NET (ESAPI.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using System.Collections;

namespace Owasp.Esapi
{
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
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IIntrusionDetector">
    /// </seealso>
    public class IntrusionDetector : IIntrusionDetector
    {
        /// <summary>The logger. </summary>
        private static readonly Logger logger;

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
                logger.LogWarning(ILogger_Fields.SECURITY, ((EnterpriseSecurityException)e).LogMessage, e);
            }
            else
            {                
                logger.LogWarning(ILogger_Fields.SECURITY, e.Message, e);
            }

            // add the exception to the current user, which may trigger a detector 
            User user = (User) Esapi.Authenticator().GetCurrentUser();            
            String eventName = e.GetType().FullName;

            // FIXME: AAA Rethink this - IntrusionExceptions which shouldn't get added to the IntrusionDetector
            if (e is IntrusionException)
            {
                return;
            }

            // add the exception to the user's store, handle IntrusionException if thrown
            try
            {
                user.AddSecurityEvent(eventName);
            }
            catch (IntrusionException ex)
            {
                Threshold quota = Esapi.SecurityConfiguration().GetQuota(eventName);
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
            logger.LogWarning(ILogger_Fields.SECURITY, "Security event " + eventName + " received");

            // add the event to the current user, which may trigger a detector 
            User user = (User) Esapi.Authenticator().GetCurrentUser();
            try
            {
                user.AddSecurityEvent("event." + eventName);
            }
            catch (IntrusionException ex)
            {
                Threshold quota = Esapi.SecurityConfiguration().GetQuota("event." + eventName);
                IEnumerator i = quota.Actions.GetEnumerator();                
                while (i.MoveNext())
                {                    
                    string action = (string)i.Current;
                    string message = "User exceeded quota of " + quota.Count + " per " + quota.Interval + " seconds for event " + eventName + ". Taking actions " + quota.Actions.ToString();
                    TakeSecurityAction(action, message);
                }
            }
        }


        /*
        * FIXME: Enhance - future actions might include SNMP traps, email, pager, etc...
        */
        /// <summary>
        /// This method performs a security action based on an intrustion threshold.
        /// </summary>
        /// <param name="action">The action to take.</param>
        /// <param name="message">The message to log regarding the action.</param>
        private void TakeSecurityAction(string action, string message)
        {
            if (action.Equals("log"))
            {
                logger.LogCritical(ILogger_Fields.SECURITY, "INTRUSION - " + message);
            }
            if (action.Equals("disable"))
            {
                Esapi.Authenticator().GetCurrentUser().Disable();
            }
            if (action.Equals("logout"))
            {
                ((Authenticator)Esapi.Authenticator()).Logout();
            }
        }


        /// <summary>
        ///  Static constructor.
        /// </summary>
        static IntrusionDetector()
        {
            logger = Logger.GetLogger("ESAPI", "IntrusionDetector");
        }
    }
}
