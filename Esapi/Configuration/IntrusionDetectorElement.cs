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

        #region Actions Property

        /// <summary>
        /// The XML name of the <see cref="ActionCollection"/> property.
        /// </summary>
        internal const string ActionsPropertyName = "actions";

        /// <summary>
        /// Gets or sets the Actions.
        /// </summary>
        [ConfigurationProperty(ActionsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public ActionCollection Actions
        {
            get
            {
                return (ActionCollection)base[ActionsPropertyName];
            }
            set
            {
                base[ActionsPropertyName] = value;
            }
        }

        #endregion

        #region Rules Property

        /// <summary>
        /// The XML name of the <see cref="Rules"/> property.
        /// </summary>
        internal const string RulesPropertyName = "rules";

        /// <summary>
        /// Gets or sets the Rules.
        /// </summary>
        [ConfigurationProperty(RulesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public RuleCollection Rules
        {
            get
            {
                return (RuleCollection)base[RulesPropertyName];
            }
            set
            {
                base[RulesPropertyName] = value;
            }
        }

        #endregion

        #region Conditions Property

        /// <summary>
        /// The XML name of the <see cref="Conditions"/> property.
        /// </summary>
        internal const string ConditionsPropertyName = "conditions";

        /// <summary>
        /// Gets or sets the Conditions.
        /// </summary>
        [ConfigurationProperty(ConditionsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public ConditionCollection Conditions
        {
            get
            {
                return (ConditionCollection)base[ConditionsPropertyName];
            }
            set
            {
                base[ConditionsPropertyName] = value;
            }
        }

        #endregion

        #region Contexts Property

        /// <summary>
        /// The XML name of the <see cref="Contexts"/> property.
        /// </summary>
        internal const string ContextsPropertyName = "contexts";

        /// <summary>
        /// Gets or sets the Contexts.
        /// </summary>
        [ConfigurationProperty(ContextsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public RuntimeContextCollection Contexts
        {
            get
            {
                return (RuntimeContextCollection)base[ContextsPropertyName];
            }
            set
            {
                base[ContextsPropertyName] = value;
            }
        }

        #endregion
    }       
}
