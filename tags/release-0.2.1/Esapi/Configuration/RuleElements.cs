using System;
using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The RuleElement Configuration Element.
    /// </summary>
    public partial class RuleElement : ObjectInstanceElement
    {
        #region Mode Property

        /// <summary>
        /// The XML name of the <see cref="Mode"/> property.
        /// </summary>
        internal const String ModePropertyName = "mode";

        /// <summary>
        /// Gets or sets the Mode.
        /// </summary>
        [ConfigurationProperty(ModePropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public String Mode
        {
            get
            {
                return (String)base[ModePropertyName];
            }
            set
            {
                base[ModePropertyName] = value;
            }
        }

        #endregion
    }

    /// <summary>
    /// A collection of RuleElement instances.
    /// </summary>
    [ConfigurationCollection(typeof(RuleElement), CollectionType = ConfigurationElementCollectionType.BasicMapAlternate, AddItemName = RuleCollection.RuleElementPropertyName)]
    public partial class RuleCollection : ConfigurationElementCollection
    {
        #region Constants

        /// <summary>
        /// The XML name of the individual <see cref="RuleElement"/> instances in this collection.
        /// </summary>
        internal const String RuleElementPropertyName = "ruleElement";

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
            return (elementName == RuleElementPropertyName);
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
            return ((RuleElement)element).Name;
        }

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new RuleElement();
        }

        #endregion

        #region Indexer

        /// <summary>
        /// Gets the <see cref="RuleElement"/> at the specified index.
        /// </summary>
        /// <param name="index">The index of the <see cref="RuleElement"/> to retrieve</param>
        public RuleElement this[int index]
        {
            get
            {
                return (RuleElement)this.BaseGet(index);
            }
        }

        #endregion

        #region Add

        /// <summary>
        /// Adds the specified <see cref="RuleElement"/>.
        /// </summary>
        /// <param name="ruleElement">The <see cref="RuleElement"/> to add.</param>
        public void Add(RuleElement ruleElement)
        {
            base.BaseAdd(ruleElement);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Removes the specified <see cref="RuleElement"/>.
        /// </summary>
        /// <param name="ruleElement">The <see cref="RuleElement"/> to remove.</param>
        public void Remove(RuleElement ruleElement)
        {
            base.BaseRemove(ruleElement);
        }

        #endregion
    }
}
