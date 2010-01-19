using System;
using System.Collections.Generic;
using Owasp.Esapi.Errors;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi
{
    /// <summary>
    /// Security event
    /// </summary>
    internal class Event: IEquatable<Event>
    {
        private string _name;
        private List<DateTime> _times;

        public Event(string name)
        {
            this._name = name;
            _times = new List<DateTime>();
        }

        public string Name
        {
            get { return _name; }
        }

        public void Increment(int maxOccurences, TimeSpan maxTimeSpan)
        {
            DateTime now = DateTime.Now;
            _times.Add(now);

            while (_times.Count > maxOccurences)
                _times.RemoveAt(_times.Count - 1);

            if (_times.Count == maxOccurences) {
                if (now - _times[maxOccurences - 1] < maxTimeSpan) {
                    throw new IntrusionException(EM.IntrusionDetector_ThresholdExceeded, string.Format(EM.InstrusionDetector_ThresholdExceeded1, _name));
                }
            }
        }

        #region Object overrides
        public override bool Equals(object obj)
        {
            return Equals(obj as Event);
        }
        #endregion

        #region IEquatable<Event> Members

        public bool Equals(Event other)
        {
            if (other == null) {
                return false;
            }
            return _name == other.Name;
        }

        #endregion
    }
}
