using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.IntrusionDetection
{   
    /// <summary>
    /// Intrusion detection action arguments
    /// </summary>
    public class IntrusionActionArgs : ActionArgs
    {
        private Threshold _threshold;

        /// <summary>
        /// Initialize action arguments
        /// </summary>
        /// <param name="threshold"></param>
        public IntrusionActionArgs(Threshold threshold)
            : base(threshold.Event)
        {
            if (threshold == null) {
                throw new ArgumentNullException("threshold");
            }
            _threshold = threshold;
        }

        /// <summary>
        /// Event threshold
        /// </summary>
        public Threshold Threshold
        {
            get { return _threshold; }
        }
    }
}
