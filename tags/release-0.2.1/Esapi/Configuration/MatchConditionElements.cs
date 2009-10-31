using System;
using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The MatchConditionElement Configuration Element.
    /// </summary>
    public partial class MatchConditionElement : ConfigurationElement
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

        #region Value Property

        /// <summary>
        /// The XML name of the <see cref="Value"/> property.
        /// </summary>
        internal const String ValuePropertyName = "value";

        /// <summary>
        /// Gets or sets the Value.
        /// </summary>
        [ConfigurationProperty(ValuePropertyName, IsRequired = true, IsKey = false, IsDefaultCollection = false)]
        public Boolean Value
        {
            get
            {
                return (Boolean)base[ValuePropertyName];
            }
            set
            {
                base[ValuePropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// A collection of MatchConditionElement instances.
    /// </summary>
    [ConfigurationCollection(typeof(MatchConditionElement), CollectionType = ConfigurationElementCollectionType.BasicMapAlternate, AddItemName = MatchConditionCollection.MatchConditionElementPropertyName)]
    public partial class MatchConditionCollection : ConfigurationElementCollection
    {
        #region Constants

        /// <summary>
        /// The XML name of the individual <see cref="MatchConditionElement"/> instances in this collection.
        /// </summary>
        internal const String MatchConditionElementPropertyName = "matchConditionElement";

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
            return (elementName == MatchConditionElementPropertyName);
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
            return ((MatchConditionElement)element).Name;
        }

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new MatchConditionElement();
        }

        #endregion

        #region Indexer

        /// <summary>
        /// Gets the <see cref="MatchConditionElement"/> at the specified index.
        /// </summary>
        /// <param name="index">The index of the <see cref="MatchConditionElement"/> to retrieve</param>
        public MatchConditionElement this[int index]
        {
            get
            {
                return (MatchConditionElement)this.BaseGet(index);
            }
        }

        #endregion

        #region Add

        /// <summary>
        /// Adds the specified <see cref="MatchConditionElement"/>.
        /// </summary>
        /// <param name="matchConditionElement">The <see cref="MatchConditionElement"/> to add.</param>
        public void Add(MatchConditionElement matchConditionElement)
        {
            base.BaseAdd(matchConditionElement);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Removes the specified <see cref="MatchConditionElement"/>.
        /// </summary>
        /// <param name="matchConditionElement">The <see cref="MatchConditionElement"/> to remove.</param>
        public void Remove(MatchConditionElement matchConditionElement)
        {
            base.BaseRemove(matchConditionElement);
        }

        #endregion
    }
}
