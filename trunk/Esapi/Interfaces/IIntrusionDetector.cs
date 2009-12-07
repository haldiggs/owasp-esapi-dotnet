using System;
using Owasp.Esapi.Runtime;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IIntrusionDetector interface is intended to track security relevant events and identify attack behavior.
    /// </summary>
    public interface IIntrusionDetector
    {
        /// <summary> 
        /// The intrusion detection quota for a particular event.
        /// </summary>
        /// <param name="threshold">
        /// The quote for a particular event name.
        /// </param>
        void AddThreshold(Threshold threshold);

        /// <summary>
        /// Remove event threshold
        /// </summary>
        /// <param name="eventName"></param>
        bool RemoveThreshold(string eventName);

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
