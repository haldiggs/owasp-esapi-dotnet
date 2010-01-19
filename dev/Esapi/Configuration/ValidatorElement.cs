using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The ValidatorElement Configuration Element.
    /// </summary>
    public class ValidatorElement : ConfigurationElement
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

        #region Rules Property

        /// <summary>
        /// The XML name of the <see cref="Rules"/> property.
        /// </summary>
        internal const string RulesPropertyName = "rules";

        /// <summary>
        /// Gets or sets the Rules.
        /// </summary>
        [ConfigurationProperty(RulesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public ValidationRuleCollection Rules
        {
            get
            {
                return (ValidationRuleCollection)base[RulesPropertyName];
            }
            set
            {
                base[RulesPropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// A collection of ValidationRuleElement instances.
    /// </summary>
    [ConfigurationCollection(typeof(ValidationRuleElement), CollectionType = ConfigurationElementCollectionType.AddRemoveClearMapAlternate)]
    public partial class ValidationRuleCollection : ConfigurationElementCollection
    {
        #region Constants

        /// <summary>
        /// The XML name of the individual <see cref="ValidationRuleElement"/> instances in this collection.
        /// </summary>
        internal const string ValidationRuleElementPropertyName = "rule";

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
                return ConfigurationElementCollectionType.AddRemoveClearMapAlternate;
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
            return (elementName == ValidationRuleElementPropertyName);
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
            return ((ValidationRuleElement)element).Name;
        }

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new ValidationRuleElement();
        }

        #endregion

        #region Indexer

        /// <summary>
        /// Gets the <see cref="ValidationRuleElement"/> at the specified index.
        /// </summary>
        /// <param name="index">The index of the <see cref="ValidationRuleElement"/> to retrieve</param>
        public ValidationRuleElement this[int index]
        {
            get
            {
                return (ValidationRuleElement)this.BaseGet(index);
            }
        }

        #endregion

        #region Add

        /// <summary>
        /// Adds the specified <see cref="ValidationRuleElement"/>.
        /// </summary>
        /// <param name="rule">The <see cref="ValidationRuleElement"/> to add.</param>
        public void Add(ValidationRuleElement rule)
        {
            base.BaseAdd(rule);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Removes the specified <see cref="ValidationRuleElement"/>.
        /// </summary>
        /// <param name="rule">The <see cref="ValidationRuleElement"/> to remove.</param>
        public void Remove(ValidationRuleElement rule)
        {
            base.BaseRemove(rule);
        }

        #endregion
        #region Assemblies Property

        /// <summary>
        /// The XML name of the <see cref="Assemblies"/> property.
        /// </summary>
        internal const string AssembliesPropertyName = "assemblies";

        /// <summary>
        /// Gets or sets the Assemblies.
        /// </summary>
        [ConfigurationProperty(AssembliesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public AddinAssemblyCollection Assemblies
        {
            get
            {
                return (AddinAssemblyCollection)base[AssembliesPropertyName];
            }
            set
            {
                base[AssembliesPropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// The ValidationRuleElement Configuration Element.
    /// </summary>
    public class ValidationRuleElement : AddinElement
    {
    }
}
