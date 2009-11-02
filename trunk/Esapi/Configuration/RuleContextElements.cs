using System;
using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The RuntimeContextElement Configuration Element.
    /// </summary>
    public partial class RuntimeContextElement : ConfigurationElement
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
        internal const String SubContextsPropertyName = "subContexts";

        /// <summary>
        /// Gets or sets the ChainedContexts.
        /// </summary>
        [ConfigurationProperty(SubContextsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public RuntimeContextCollection SubContexts
        {
            get
            {
                return (RuntimeContextCollection)base[SubContextsPropertyName];
            }
            set
            {
                base[SubContextsPropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// A collection of RuntimeContextElement instances.
    /// </summary>
    [ConfigurationCollection(typeof(RuntimeContextElement), CollectionType = ConfigurationElementCollectionType.BasicMapAlternate, AddItemName = RuntimeContextCollection.RuntimeContextElementPropertyName)]
    public partial class RuntimeContextCollection : ConfigurationElementCollection
    {
        #region Constants

        /// <summary>
        /// The XML name of the individual <see cref="RuntimeContextElement"/> instances in this collection.
        /// </summary>
        internal const String RuntimeContextElementPropertyName = "contextElement";

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
            return (elementName == RuntimeContextElementPropertyName);
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
            return ((RuntimeContextElement)element).Name;
        }

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new RuntimeContextElement();
        }

        #endregion

        #region Indexer

        /// <summary>
        /// Gets the <see cref="RuntimeContextElement"/> at the specified index.
        /// </summary>
        /// <param name="index">The index of the <see cref="RuntimeContextElement"/> to retrieve</param>
        public RuntimeContextElement this[int index]
        {
            get
            {
                return (RuntimeContextElement)this.BaseGet(index);
            }
        }

        #endregion

        #region Add

        /// <summary>
        /// Adds the specified <see cref="RuntimeContextElement"/>.
        /// </summary>
        /// <param name="contextElement">The <see cref="RuntimeContextElement"/> to add.</param>
        public void Add(RuntimeContextElement contextElement)
        {
            base.BaseAdd(contextElement);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Removes the specified <see cref="RuntimeContextElement"/>.
        /// </summary>
        /// <param name="contextElement">The <see cref="RuntimeContextElement"/> to remove.</param>
        public void Remove(RuntimeContextElement contextElement)
        {
            base.BaseRemove(contextElement);
        }

        #endregion
    }
}
