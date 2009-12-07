using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The IntrusionDetectorElement Configuration Element.
    /// </summary>
    public class IntrusionDetectorElement : ConfigurationElement
    {
        #region Type Property

        /// <summary>
        /// The XML name of the <see cref="Type"/> property.
        /// </summary>
        internal const string TypePropertyName = "type";

        /// <summary>
        /// Gets or sets the Type.
        /// </summary>
        [ConfigurationProperty(TypePropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public string Type
        {
            get
            {
                return (string)base[TypePropertyName];
            }
            set
            {
                base[TypePropertyName] = value;
            }
        }

        #endregion

        #region EventThresholds Property

        /// <summary>
        /// The XML name of the <see cref="EventThresholds"/> property.
        /// </summary>
        internal const string EventThresholdsPropertyName = "eventThresholds";

        /// <summary>
        /// Gets or sets the EventThresholds.
        /// </summary>
        [ConfigurationProperty(EventThresholdsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public EventThresholdCollection EventThresholds
        {
            get
            {
                return (EventThresholdCollection)base[EventThresholdsPropertyName];
            }
            set
            {
                base[EventThresholdsPropertyName] = value;
            }
        }

        #endregion
    }       
}
