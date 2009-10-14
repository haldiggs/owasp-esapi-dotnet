using System;
using System.Collections.Generic;
using System.Text;
using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The SecurityConfigurationElement Configuration Element.
    /// </summary>
    public class SecurityConfigurationElement : ConfigurationElement
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

        #region Algorithms Property

        /// <summary>
        /// The XML name of the <see cref="Algorithms"/> property.
        /// </summary>
        internal const string AlgorithmsPropertyName = "algorithms";

        /// <summary>
        /// Gets or sets the Algorithms.
        /// </summary>
        [ConfigurationProperty(AlgorithmsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public AlgorithmsConfigurationElement Algorithms
        {
            get
            {
                return (AlgorithmsConfigurationElement)base[AlgorithmsPropertyName];
            }
            set
            {
                base[AlgorithmsPropertyName] = value;
            }
        }

        #endregion

        #region Encryption Property

        /// <summary>
        /// The XML name of the <see cref="Encryption"/> property.
        /// </summary>
        internal const string EncryptionPropertyName = "encryption";

        /// <summary>
        /// Gets or sets the Encryption.
        /// </summary>
        [ConfigurationProperty(EncryptionPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public EncryptionConfigurationElement Encryption
        {
            get
            {
                return (EncryptionConfigurationElement)base[EncryptionPropertyName];
            }
            set
            {
                base[EncryptionPropertyName] = value;
            }
        }

        #endregion

        #region Application Property

        /// <summary>
        /// The XML name of the <see cref="Application"/> property.
        /// </summary>
        internal const string ApplicationPropertyName = "application";

        /// <summary>
        /// Gets or sets the Application.
        /// </summary>
        [ConfigurationProperty(ApplicationPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public ApplicationConfigurationElement Application
        {
            get
            {
                return (ApplicationConfigurationElement)base[ApplicationPropertyName];
            }
            set
            {
                base[ApplicationPropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// The AlgorithmsConfigurationElement Configuration Element.
    /// </summary>
    public class AlgorithmsConfigurationElement : ConfigurationElement
    {
        #region Encryption Property

        /// <summary>
        /// The XML name of the <see cref="Encryption"/> property.
        /// </summary>
        internal const string EncryptionPropertyName = "encryption";

        /// <summary>
        /// Gets or sets the Encryption.
        /// </summary>
        [ConfigurationProperty(EncryptionPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Rijndael")]
        public string Encryption
        {
            get
            {
                return (string)base[EncryptionPropertyName];
            }
            set
            {
                base[EncryptionPropertyName] = value;
            }
        }

        #endregion

        #region Hash Property

        /// <summary>
        /// The XML name of the <see cref="Hash"/> property.
        /// </summary>
        internal const string HashPropertyName = "hash";

        /// <summary>
        /// Gets or sets the Hash.
        /// </summary>
        [ConfigurationProperty(HashPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "SHA512")]
        public string Hash
        {
            get
            {
                return (string)base[HashPropertyName];
            }
            set
            {
                base[HashPropertyName] = value;
            }
        }

        #endregion

        #region Random Property

        /// <summary>
        /// The XML name of the <see cref="Random"/> property.
        /// </summary>
        internal const string RandomPropertyName = "random";

        /// <summary>
        /// Gets or sets the Random.
        /// </summary>
        [ConfigurationProperty(RandomPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "System.Security.Cryptography.RNGCryptoServiceProvider")]
        public string Random
        {
            get
            {
                return (string)base[RandomPropertyName];
            }
            set
            {
                base[RandomPropertyName] = value;
            }
        }

        #endregion

        #region DigitalSignature Property

        /// <summary>
        /// The XML name of the <see cref="DigitalSignature"/> property.
        /// </summary>
        internal const string DigitalSignaturePropertyName = "digitalSignature";

        /// <summary>
        /// Gets or sets the DigitalSignature.
        /// </summary>
        [ConfigurationProperty(DigitalSignaturePropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "DSA")]
        public string DigitalSignature
        {
            get
            {
                return (string)base[DigitalSignaturePropertyName];
            }
            set
            {
                base[DigitalSignaturePropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// The EncryptionConfigurationElement Configuration Element.
    /// </summary>
    public class EncryptionConfigurationElement : ConfigurationElement
    {
        #region MasterPassword Property

        /// <summary>
        /// The XML name of the <see cref="MasterPassword"/> property.
        /// </summary>
        internal const string MasterPasswordPropertyName = "masterPassword";

        /// <summary>
        /// Gets or sets the MasterPassword.
        /// </summary>
        [ConfigurationProperty(MasterPasswordPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public string MasterPassword
        {
            get
            {
                return (string)base[MasterPasswordPropertyName];
            }
            set
            {
                base[MasterPasswordPropertyName] = value;
            }
        }

        #endregion

        #region MasterSalt Property

        /// <summary>
        /// The XML name of the <see cref="MasterSalt"/> property.
        /// </summary>
        internal const string MasterSaltPropertyName = "masterSalt";

        /// <summary>
        /// Gets or sets the MasterSalt.
        /// </summary>
        [ConfigurationProperty(MasterSaltPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "7FB22E3EAD054696A221204CF32F5400")]
        public string MasterSalt
        {
            get
            {
                return (string)base[MasterSaltPropertyName];
            }
            set
            {
                base[MasterSaltPropertyName] = value;
            }
        }

        #endregion

    }

    /// <summary>
    /// The ApplicationConfigurationElement Configuration Element.
    /// </summary>
    public class ApplicationConfigurationElement : ConfigurationElement
    {
        #region UploadValidExtensions Property

        /// <summary>
        /// The XML name of the <see cref="UploadValidExtensions"/> property.
        /// </summary>
        internal const string UploadValidExtensionsPropertyName = "uploadValidExtensions";

        /// <summary>
        /// Gets or sets the UploadValidExtensions.
        /// </summary>
        [ConfigurationProperty(UploadValidExtensionsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml")]
        public string UploadValidExtensions
        {
            get
            {
                return (string)base[UploadValidExtensionsPropertyName];
            }
            set
            {
                base[UploadValidExtensionsPropertyName] = value;
            }
        }

        #endregion

        #region UploadMaxSize Property

        /// <summary>
        /// The XML name of the <see cref="UploadMaxSize"/> property.
        /// </summary>
        internal const string UploadMaxSizePropertyName = "uploadMaxSize";

        /// <summary>
        /// Gets or sets the UploadMaxSize.
        /// </summary>
        [ConfigurationProperty(UploadMaxSizePropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "50000")]
        public int UploadMaxSize
        {
            get
            {
                return (int)base[UploadMaxSizePropertyName];
            }
            set
            {
                base[UploadMaxSizePropertyName] = value;
            }
        }

        #endregion

        #region CharacterEncoding Property

        /// <summary>
        /// The XML name of the <see cref="CharacterEncoding"/> property.
        /// </summary>
        internal const string CharacterEncodingPropertyName = "characterEncoding";

        /// <summary>
        /// Gets or sets the CharacterEncoding.
        /// </summary>
        [ConfigurationProperty(CharacterEncodingPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "UTF-8")]
        public string CharacterEncoding
        {
            get
            {
                return (string)base[CharacterEncodingPropertyName];
            }
            set
            {
                base[CharacterEncodingPropertyName] = value;
            }
        }

        #endregion

        #region ResponseContentType Property

        /// <summary>
        /// The XML name of the <see cref="ResponseContentType"/> property.
        /// </summary>
        internal const string ResponseContentTypePropertyName = "responseContentType";

        /// <summary>
        /// Gets or sets the ResponseContentType.
        /// </summary>
        [ConfigurationProperty(ResponseContentTypePropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "text/html; charset=UTF-8")]
        public string ResponseContentType
        {
            get
            {
                return (string)base[ResponseContentTypePropertyName];
            }
            set
            {
                base[ResponseContentTypePropertyName] = value;
            }
        }

        #endregion

        #region LogLevel Property

        /// <summary>
        /// The XML name of the <see cref="LogLevel"/> property.
        /// </summary>
        internal const string LogLevelPropertyName = "logLevel";

        /// <summary>
        /// Gets or sets the LogLevel.
        /// </summary>
        [ConfigurationProperty(LogLevelPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "ALL")]
        public string LogLevel
        {
            get
            {
                return (string)base[LogLevelPropertyName];
            }
            set
            {
                base[LogLevelPropertyName] = value;
            }
        }

        #endregion

        #region MaxRedirectLocation Property

        /// <summary>
        /// The XML name of the <see cref="MaxRedirectLocation"/> property.
        /// </summary>
        internal const string MaxRedirectLocationPropertyName = "maxRedirectLocation";

        /// <summary>
        /// Gets or sets the MaxRedirectLocation.
        /// </summary>
        [ConfigurationProperty(MaxRedirectLocationPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "1000")]
        public int MaxRedirectLocation
        {
            get
            {
                return (int)base[MaxRedirectLocationPropertyName];
            }
            set
            {
                base[MaxRedirectLocationPropertyName] = value;
            }
        }

        #endregion

        #region MaxFileNameLength Property

        /// <summary>
        /// The XML name of the <see cref="MaxFileNameLength"/> property.
        /// </summary>
        internal const string MaxFileNameLengthPropertyName = "maxFileNameLength";

        /// <summary>
        /// Gets or sets the MaxFileNameLength.
        /// </summary>
        [ConfigurationProperty(MaxFileNameLengthPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "1000")]
        public int MaxFileNameLength
        {
            get
            {
                return (int)base[MaxFileNameLengthPropertyName];
            }
            set
            {
                base[MaxFileNameLengthPropertyName] = value;
            }
        }

        #endregion

        #region LogEncodingRequired Property

        /// <summary>
        /// The XML name of the <see cref="LogEncodingRequired"/> property.
        /// </summary>
        internal const string LogEncodingRequiredPropertyName = "logEncodingRequired";

        /// <summary>
        /// Gets or sets the LogEncodingRequired.
        /// </summary>
        [ConfigurationProperty(LogEncodingRequiredPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "false")]
        public bool LogEncodingRequired
        {
            get
            {
                return (bool)base[LogEncodingRequiredPropertyName];
            }
            set
            {
                base[LogEncodingRequiredPropertyName] = value;
            }
        }

        #endregion

    }
}
