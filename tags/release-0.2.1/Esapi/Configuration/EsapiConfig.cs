using System.Configuration;
using System.Threading;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The EsapiConfig Configuration Section.
    /// </summary>
    public class EsapiConfig : ConfigurationSection
    {
        #region AccessController Property

        /// <summary>
        /// The XML name of the <see cref="AccessController"/> property.
        /// </summary>
        internal const string AccessControllerPropertyName = "accessController";

        /// <summary>
        /// Gets or sets the AccessController.
        /// </summary>
        [ConfigurationProperty(AccessControllerPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public AccessControllerElement AccessController
        {
            get
            {
                return (AccessControllerElement)base[AccessControllerPropertyName];
            }
            set
            {
                base[AccessControllerPropertyName] = value;
            }
        }

        #endregion

        #region Encoder Property

        /// <summary>
        /// The XML name of the <see cref="Encoder"/> property.
        /// </summary>
        internal const string EncoderPropertyName = "encoder";

        /// <summary>
        /// Gets or sets the Encoder.
        /// </summary>
        [ConfigurationProperty(EncoderPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public EncoderElement Encoder
        {
            get
            {
                return (EncoderElement)base[EncoderPropertyName];
            }
            set
            {
                base[EncoderPropertyName] = value;
            }
        }

        #endregion

        #region Encryptor Property

        /// <summary>
        /// The XML name of the <see cref="Encryptor"/> property.
        /// </summary>
        internal const string EncryptorPropertyName = "encryptor";

        /// <summary>
        /// Gets or sets the Encryptor.
        /// </summary>
        [ConfigurationProperty(EncryptorPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public EncryptorElement Encryptor
        {
            get
            {
                return (EncryptorElement)base[EncryptorPropertyName];
            }
            set
            {
                base[EncryptorPropertyName] = value;
            }
        }

        #endregion

        #region IntrusionDetector Property

        /// <summary>
        /// The XML name of the <see cref="IntrusionDetector"/> property.
        /// </summary>
        internal const string IntrusionDetectorPropertyName = "intrusionDetector";

        /// <summary>
        /// Gets or sets the IntrusionDetector.
        /// </summary>
        [ConfigurationProperty(IntrusionDetectorPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public IntrusionDetectorElement IntrusionDetector
        {
            get
            {
                return (IntrusionDetectorElement)base[IntrusionDetectorPropertyName];
            }
            set
            {
                base[IntrusionDetectorPropertyName] = value;
            }
        }

        #endregion

        #region Randomizer Property

        /// <summary>
        /// The XML name of the <see cref="Randomizer"/> property.
        /// </summary>
        internal const string RandomizerPropertyName = "randomizer";

        /// <summary>
        /// Gets or sets the Randomizer.
        /// </summary>
        [ConfigurationProperty(RandomizerPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public RandomizerElement Randomizer
        {
            get
            {
                return (RandomizerElement)base[RandomizerPropertyName];
            }
            set
            {
                base[RandomizerPropertyName] = value;
            }
        }

        #endregion

        #region Validator Property

        /// <summary>
        /// The XML name of the <see cref="Validator"/> property.
        /// </summary>
        internal const string ValidatorPropertyName = "validator";

        /// <summary>
        /// Gets or sets the Validator.
        /// </summary>
        [ConfigurationProperty(ValidatorPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public ValidatorElement Validator
        {
            get
            {
                return (ValidatorElement)base[ValidatorPropertyName];
            }
            set
            {
                base[ValidatorPropertyName] = value;
            }
        }

        #endregion

        #region HttpUtilities Property

        /// <summary>
        /// The XML name of the <see cref="HttpUtilities"/> property.
        /// </summary>
        internal const string HttpUtilitiesPropertyName = "httpUtilities";

        /// <summary>
        /// Gets or sets the HttpUtilities.
        /// </summary>
        [ConfigurationProperty(HttpUtilitiesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public HttpUtilitiesElement HttpUtilities
        {
            get
            {
                return (HttpUtilitiesElement)base[HttpUtilitiesPropertyName];
            }
            set
            {
                base[HttpUtilitiesPropertyName] = value;
            }
        }

        #endregion

        #region SecurityConfiguration Property

        /// <summary>
        /// The XML name of the <see cref="SecurityConfiguration"/> property.
        /// </summary>
        internal const string SecurityConfigurationPropertyName = "securityConfiguration";

        /// <summary>
        /// Gets or sets the SecurityConfiguration.
        /// </summary>
        [ConfigurationProperty(SecurityConfigurationPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public SecurityConfigurationElement SecurityConfiguration
        {
            get
            {
                return (SecurityConfigurationElement)base[SecurityConfigurationPropertyName];
            }
            set
            {
                base[SecurityConfigurationPropertyName] = value;
            }
        }

        #endregion

        #region Singleton Instance

        /// <summary>
        /// The XML name of the EsapiConfig Configuration Section.
        /// </summary>
        internal const string EsapiConfigSectionName = "esapi";

        /// <summary>
        /// Instance singleton
        /// </summary>
        private static EsapiConfig _instance;
        private static object _instanceLock = new object();

        /// <summary>
        /// Gets the EsapiConfig instance.
        /// </summary>
        public static EsapiConfig Instance
        {
            get
            {
                if (_instance == null) {
                    lock (_instanceLock) {
                        if (_instance == null) {
                            Thread.MemoryBarrier();

                            _instance = ConfigurationManager.GetSection(EsapiConfigSectionName) as EsapiConfig;
                            if (_instance == null) {
                                _instance = new EsapiConfig();
                            }
                        }
                    }
                }
                return _instance;
            }
        }

        /// <summary>
        /// Reset config instance
        /// </summary>
        internal static void Reset()
        {
            lock (_instanceLock) {
                _instance = null;
            }
        }

        #endregion

        #region Xmlns Property

        /// <summary>
        /// The XML name of the <see cref="Xmlns"/> property.
        /// </summary>
        internal const string XmlnsPropertyName = "xmlns";

        /// <summary>
        /// Gets the XML namespace of this Configuration Section.
        /// </summary>
        /// <remarks>
        /// This property makes sure that if the configuration file contains the XML namespace,
        /// the parser doesn't throw an exception because it encounters the unknown "xmlns" attribute.
        /// </remarks>
        [ConfigurationProperty(XmlnsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public string Xmlns
        {
            get
            {
                return (string)base[XmlnsPropertyName];
            }
        }

        #endregion
    }

    /// <summary>
	/// The AddinAssemblyElement Configuration Element.
	/// </summary>
	public class AddinAssemblyElement : ConfigurationElement
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

		#region Types Property
		
		/// <summary>
		/// The XML name of the <see cref="Types"/> property.
		/// </summary>
		internal const string TypesPropertyName = "types";
		
		/// <summary>
		/// Gets or sets the Types.
		/// </summary>
		[ConfigurationProperty(TypesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "*")]
		public string Types
		{
			get
			{
				return (string)base[TypesPropertyName];
			}
			set
			{
				base[TypesPropertyName] = value;
			}
		}
		
		#endregion

	}

    /// <summary>
	/// A collection of AddinAssemblyElement instances.
	/// </summary>
	[ConfigurationCollection(typeof(AddinAssemblyElement), CollectionType = ConfigurationElementCollectionType.AddRemoveClearMapAlternate)]
	public class AddinAssemblyCollection : ConfigurationElementCollection
	{
		#region Constants
		
		/// <summary>
		/// The XML name of the individual <see cref="AddinAssemblyElement"/> instances in this collection.
		/// </summary>
		internal const string AddinAssemblyElementPropertyName = "assembly";

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
			return (elementName == AddinAssemblyElementPropertyName);
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
			return ((AddinAssemblyElement)element).Name;
		}

		/// <summary>
		/// When overridden in a derived class, creates a new <see cref="ConfigurationElement"/>.
		/// </summary>
		/// <returns>
		/// A new <see cref="ConfigurationElement"/>.
		/// </returns>
		protected override ConfigurationElement CreateNewElement()
		{
			return new AddinAssemblyElement();
		}

		#endregion
		
		#region Indexer

		/// <summary>
		/// Gets the <see cref="AddinAssemblyElement"/> at the specified index.
		/// </summary>
		/// <param name="index">The index of the <see cref="AddinAssemblyElement"/> to retrieve</param>
		public AddinAssemblyElement this[int index]
		{
			get
			{
				return (AddinAssemblyElement)this.BaseGet(index);
			}
		}

		#endregion
		
		#region Add

		/// <summary>
		/// Adds the specified <see cref="AddinAssemblyElement"/>.
		/// </summary>
		/// <param name="assembly">The <see cref="AddinAssemblyElement"/> to add.</param>
		public void Add(AddinAssemblyElement assembly)
		{
			base.BaseAdd(assembly);
		}

		#endregion
		
		#region Remove

		/// <summary>
		/// Removes the specified <see cref="AddinAssemblyElement"/>.
		/// </summary>
		/// <param name="assembly">The <see cref="AddinAssemblyElement"/> to remove.</param>
		public void Remove(AddinAssemblyElement assembly)
		{
			base.BaseRemove(assembly);
		}

		#endregion
	}
}
