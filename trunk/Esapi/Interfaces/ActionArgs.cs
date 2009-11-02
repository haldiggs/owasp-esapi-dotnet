using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// ESAPI action arguments
    /// </summary>
    [Serializable]
    public class ActionArgs
    {
        /// <summary>
        /// Empty action arguments
        /// </summary>
        public static readonly ActionArgs Empty;

        static ActionArgs()
        {
            Empty = new ActionArgs(string.Empty);
        }

        private string _eventName;

        /// <summary>
        /// Initialize action arguments
        /// </summary>
        /// <param name="eventName"></param>
        public ActionArgs(string eventName)
        {
            _eventName = eventName;
        }
        /// <summary>
        /// Get event name
        /// </summary>
        public string Event
        {
            get { return _eventName; }
        }
    }
}
