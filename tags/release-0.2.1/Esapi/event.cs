using System;
using System.Collections.Generic;
using Owasp.Esapi.Errors;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi
{
    /// <summary>
    /// Security event
    /// </summary>
    internal class Event
    {
        private string _key;
        private List<DateTime> _times;

        public Event(string key)
        {
            this._key = key;
            _times = new List<DateTime>();
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
}
