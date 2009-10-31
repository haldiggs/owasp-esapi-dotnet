using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IIntrusionDetector interface is intended to track security relevant events and identify attack behavior.
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
