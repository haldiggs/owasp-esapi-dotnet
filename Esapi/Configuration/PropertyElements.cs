using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// A collection of Property instances.
    /// </summary>
    [ConfigurationCollection(typeof(Property), CollectionType = ConfigurationElementCollectionType.AddRemoveClearMap)]
    public partial class PropertyCollection : ConfigurationElementCollection
    {
        #region Constants

        /// <summary>
        /// The XML name of the individual <see cref="Property"/> instances in this collection.
        /// </summary>
        internal const string PropertyPropertyName = "property";

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
                return ConfigurationElementCollectionType.AddRemoveClearMap;
            }
        }

        /// <summary>
        /// Indicates whether the specified <see cref="ConfigurationElement"/> exists in the <see cref="ConfigurationElementCollection"/>.
        /// </summary>
        /// <param name="elementName">The name of the element to verify.</param>
        /// <returns>
        /// <see langword="true"/> if the element exists in the collection; otherwise, <see langword="false"/>. The default is <see langword="false"/>.
        /// </returns>
        protected override bool IsElementName(string elementName)
        {
            return (elementName == PropertyPropertyName);
        }

        /// <summary>
        /// Gets the element key for a specified configuration element when overridden in a derived class.
        /// </summary>
        /// <param name="element">The <see cref="ConfigurationElement"/> to return the key for.</param>
        /// <returns>
        /// An <see cref="object"/> that acts as the key for the specified <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((Property)element).Name;
        }

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new Property();
        }

        #endregion

        #region Indexer

        /// <summary>
        /// Gets the <see cref="Property"/> at the specified index.
        /// </summary>
        /// <param name="index">The index of the <see cref="Property"/> to retrieve</param>
        public Property this[int index]
        {
            get
            {
                return (Property)this.BaseGet(index);
            }
        }

        #endregion

        #region Add

        /// <summary>
        /// Adds the specified <see cref="Property"/>.
        /// </summary>
        /// <param name="property">The <see cref="Property"/> to add.</param>
        public void Add(Property property)
        {
            base.BaseAdd(property);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Removes the specified <see cref="Property"/>.
        /// </summary>
        /// <param name="property">The <see cref="Property"/> to remove.</param>
        public void Remove(Property property)
        {
            base.BaseRemove(property);
        }

        #endregion
    }

    /// <summary>
    /// The Property Configuration Element.
    /// </summary>
    public partial class Property : ConfigurationElement
    {
        #region Name Property

        /// <summary>
        /// The XML name of the <see cref="Name"/> property.
        /// </summary>
        internal const string NamePropertyName = "name";

        /// <summary>
        /// Gets or sets the Name.
        /// </summary>
        [ConfigurationProperty(NamePropertyName, IsRequired = true, IsKey = true, IsDefaultCollection = false)]
        public string Name
        {
            get
            {
                return (string)base[NamePropertyName];
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
        internal const string ValuePropertyName = "value";

        /// <summary>
        /// Gets or sets the Value.
        /// </summary>
        [ConfigurationProperty(ValuePropertyName, IsRequired = true, IsKey = false, IsDefaultCollection = false)]
        public string Value
        {
            get
            {
                return (string)base[ValuePropertyName];
            }
            set
            {
                base[ValuePropertyName] = value;
            }
        }

        #endregion

    }
}
