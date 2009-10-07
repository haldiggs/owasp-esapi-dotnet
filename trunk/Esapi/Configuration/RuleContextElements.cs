using System;
using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The RuleContextElement Configuration Element.
    /// </summary>
    public partial class RuleContextElement : ConfigurationElement
    {
        #region Name Property

        /// <summary>
        /// The XML name of the <see cref="Name"/> property.
        /// </summary>
        internal const String NamePropertyName = "name";

        /// <summary>
        /// Gets or sets the Name.
        /// </summary>
        [ConfigurationProperty(NamePropertyName, IsRequired = true, IsKey = true, IsDefaultCollection = false)]
        public String Name
        {
            get
            {
                return (String)base[NamePropertyName];
            }
            set
            {
                base[NamePropertyName] = value;
            }
        }

        #endregion

        #region MatchConditions Property

        /// <summary>
        /// The XML name of the <see cref="MatchConditions"/> property.
        /// </summary>
        internal const String MatchConditionsPropertyName = "matchConditions";

        /// <summary>
        /// Gets or sets the MatchConditions.
        /// </summary>
        [ConfigurationProperty(MatchConditionsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public MatchConditionCollection MatchConditions
        {
            get
            {
                return (MatchConditionCollection)base[MatchConditionsPropertyName];
            }
            set
            {
                base[MatchConditionsPropertyName] = value;
            }
        }

        #endregion

        #region ExecuteRules Property

        /// <summary>
        /// The XML name of the <see cref="ExecuteRules"/> property.
        /// </summary>
        internal const String ExecuteRulesPropertyName = "executeRules";

        /// <summary>
        /// Gets or sets the ExecuteRules.
        /// </summary>
        [ConfigurationProperty(ExecuteRulesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public ExecuteRuleCollection ExecuteRules
        {
            get
            {
                return (ExecuteRuleCollection)base[ExecuteRulesPropertyName];
            }
            set
            {
                base[ExecuteRulesPropertyName] = value;
            }
        }

        #endregion

        #region ChainedContexts Property

        /// <summary>
        /// The XML name of the <see cref="ChainedContexts"/> property.
        /// </summary>
        internal const String ChainedContextsPropertyName = "chainedContexts";

        /// <summary>
        /// Gets or sets the ChainedContexts.
        /// </summary>
        [ConfigurationProperty(ChainedContextsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public NamedCollection ChainedContexts
        {
            get
            {
                return (NamedCollection)base[ChainedContextsPropertyName];
            }
            set
            {
                base[ChainedContextsPropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// A collection of RuleContextElement instances.
    /// </summary>
    [ConfigurationCollection(typeof(RuleContextElement), CollectionType = ConfigurationElementCollectionType.BasicMapAlternate, AddItemName = RuleContextCollection.RuleContextElementPropertyName)]
    public partial class RuleContextCollection : ConfigurationElementCollection
    {
        #region Constants

        /// <summary>
        /// The XML name of the individual <see cref="RuleContextElement"/> instances in this collection.
        /// </summary>
        internal const String RuleContextElementPropertyName = "contextElement";

        #endregion

        #region Overrides

        /// <summary>
        /// Gets the type of the <see cref="ConfigurationElementCollection"/>.
        /// </summary>
        /// <returns>The <see cref="ConfigurationElementCollectionType"/> of this collection.</returns>
        public override ConfigurationElementCollectionType CollectionType
        {
            get
            {
                return ConfigurationElementCollectionType.BasicMapAlternate;
            }
        }

        /// <summary>
        /// Indicates whether the specified <see cref="ConfigurationElement"/> exists in the <see cref="ConfigurationElementCollection"/>.
        /// </summary>
        /// <param name="elementName">The name of the element to verify.</param>
        /// <returns>
        /// <see langword="true"/> if the element exists in the collection; otherwise, <see langword="false"/>. The default is <see langword="false"/>.
        /// </returns>
        protected override Boolean IsElementName(String elementName)
        {
            return (elementName == RuleContextElementPropertyName);
        }

        /// <summary>
        /// Gets the element key for a specified configuration element when overridden in a derived class.
        /// </summary>
        /// <param name="element">The <see cref="ConfigurationElement"/> to return the key for.</param>
        /// <returns>
        /// An <see cref="Object"/> that acts as the key for the specified <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override Object GetElementKey(ConfigurationElement element)
        {
            return ((RuleContextElement)element).Name;
        }

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new RuleContextElement();
        }

        #endregion

        #region Indexer

        /// <summary>
        /// Gets the <see cref="RuleContextElement"/> at the specified index.
        /// </summary>
        /// <param name="index">The index of the <see cref="RuleContextElement"/> to retrieve</param>
        public RuleContextElement this[int index]
        {
            get
            {
                return (RuleContextElement)this.BaseGet(index);
            }
        }

        #endregion

        #region Add

        /// <summary>
        /// Adds the specified <see cref="RuleContextElement"/>.
        /// </summary>
        /// <param name="contextElement">The <see cref="RuleContextElement"/> to add.</param>
        public void Add(RuleContextElement contextElement)
        {
            base.BaseAdd(contextElement);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Removes the specified <see cref="RuleContextElement"/>.
        /// </summary>
        /// <param name="contextElement">The <see cref="RuleContextElement"/> to remove.</param>
        public void Remove(RuleContextElement contextElement)
        {
            base.BaseRemove(contextElement);
        }

        #endregion
    }
}
