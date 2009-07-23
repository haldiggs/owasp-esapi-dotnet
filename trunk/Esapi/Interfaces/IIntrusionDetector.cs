using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IIntrusionDetector interface is intended to track security relevant events and identify attack behavior. The
    /// implementation can use as much state as necessary to detect attacks, but note that storing too much state will burden
    /// your system.
    /// The interface is currently designed to accept exceptions as well as custom events. Implementations can use this
    /// stream of information to detect both normal and abnormal behavior.    
    /// </summary>
    public interface IIntrusionDetector
    {
        /// <summary> Adds the exception to the IntrusionDetector.
        /// </summary>
        /// <param name="exception">The exception to add.
        /// </param>        
        void AddException(Exception exception);

        /// <summary> Adds the event to the IntrusionDetector.        
        /// </summary>
        /// <param name="eventName">The event to add.
        /// </param>        
        void AddEvent(string eventName);
    }
}
