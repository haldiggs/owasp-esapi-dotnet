using System;
using System.Collections;
using System.Collections.Specialized;
using System.Text;
using System.Text.RegularExpressions;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{

    /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration"/>
    /// <remarks>The SecurityConfiguration manages all the settings used by the ESAPI in a single place. Initializing the
    /// Configuration is critically important to getting the ESAPI working properly.
    /// 
    /// You must have the relevant configuration in your config file (app.config, web.config).
    /// 
    /// See the app.config file in the EsapiTest project and copy the values over.  
    /// </remarks>
    public class SecurityConfiguration : ISecurityConfiguration
    {

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.MasterPassword"/>
        public string MasterPassword
        {
            get
            {
                return properties[MASTER_PASSWORD];
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.MasterSalt"/>
        public byte[] MasterSalt
        {
            get
            {
                return new ASCIIEncoding().GetBytes(MASTER_SALT);
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.AllowedFileExtensions"/>
        public IList AllowedFileExtensions
        {
            get
            {
                string def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
                string[] extList = Regex.Split((properties[VALID_EXTENSIONS] == null ? def : properties[VALID_EXTENSIONS]), ",");
                return new ArrayList(extList);
            }

        }
       
        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.AllowedFileUploadSize"/>
        public int AllowedFileUploadSize
        {
            get
            {
                string bytes = properties[MAX_UPLOAD_FILE_BYTES] == null ? "50000" : properties[MAX_UPLOAD_FILE_BYTES];
                return Int32.Parse(bytes);
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.EncryptionAlgorithm"/>
        public string EncryptionAlgorithm
        {
            get
            {
                return properties[ENCRYPTION_ALGORITHM];
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.HashAlgorithm"/>
        public string HashAlgorithm
        {
            get
            {
                return properties[HASH_ALGORITHM];
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.CharacterEncoding"/>
        public string CharacterEncoding
        {
            get
            {
                return properties[CHARACTER_ENCODING];
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.DigitalSignatureAlgorithm"/>
        public string DigitalSignatureAlgorithm
        {
            get
            {
                return properties[DIGITAL_SIGNATURE_ALGORITHM];
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.RandomAlgorithm"/>
        public string RandomAlgorithm
        {
            get
            {
                return properties[RANDOM_ALGORITHM];
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.LogLevel"/>
        public int LogLevel
        {
            get
            {
                string level = properties.Get(LOG_LEVEL);
                return LogLevels.ParseLogLevel(level);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.LogEncodingRequired"/>
        public bool LogEncodingRequired
        {
            get
            {
                string logEncodingRequired = properties.Get("LogEncodingRequired");
                if (logEncodingRequired != null && logEncodingRequired.ToUpper().Equals("false".ToUpper()))
                    return false;
                return true;
            }

        }
        
        /// <summary>The properties. </summary>    
        private NameValueCollection properties = new NameValueCollection();

        /// <summary>The logger. </summary>                
        private static readonly ILogger logger = Esapi.Logger;

        /// <summary>
        /// The key for the resources directory property.
        /// </summary>
        public const string RESOURCE_DIRECTORY = "Owasp.Esapi.Resources";

        private const string MASTER_PASSWORD = "MasterPassword";

        private const string MASTER_SALT = "MasterSalt";

        private const string VALID_EXTENSIONS = "ValidExtensions";

        private const string MAX_UPLOAD_FILE_BYTES = "MaxUploadFileBytes";
        
        private const string ENCRYPTION_ALGORITHM = "EncryptionAlgorithm";

        private const string HASH_ALGORITHM = "HashAlgorithm";

        private const string CHARACTER_ENCODING = "CharacterEncoding";

        private const string RANDOM_ALGORITHM = "RandomAlgorithm";

        private const string DIGITAL_SIGNATURE_ALGORITHM = "DigitalSignatureAlgorithm";

        private const string RESPONSE_CONTENT_TYPE = "ResponseContentType";

        private const string LOG_LEVEL = "LogLevel";

        /// <summary>
        /// The maximum length of a redirect URL
        /// </summary>
        protected const int MAX_REDIRECT_LOCATION = 1000;
    
        /// <summary>
        /// The maximum length of a file name
        /// </summary>
        protected const int MAX_FILE_NAME_LENGTH = 1000;

        /// <summary> Instantiates a new configuration.</summary>
        public SecurityConfiguration()
        {
            LoadConfiguration();
        }

        /// <summary> Loads the configuration.</summary>        
        private void LoadConfiguration()
        {
            properties = (NameValueCollection)System.Configuration.ConfigurationManager.GetSection("esapi");       
            IEnumerator i = properties.GetEnumerator();            
            while (i.MoveNext())
            {                
                string key = (string)i.Current;
                Console.WriteLine("  |   " + key + "=" + properties[(string)key]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.GetQuota(string)" />
        public Threshold GetQuota(string eventName)
        {
            int count = 0;
            string countString = properties.Get(eventName + ".count");
            if (countString != null)
            {
                count = Int32.Parse(countString);
            }

            int interval = 0;
            string intervalString = properties.Get(eventName + ".interval");
            if (intervalString != null)
            {
                interval = Int32.Parse(intervalString);
            }

            IList actions = new ArrayList();
            string actionString = properties.Get(eventName + ".actions");
            if (actionString != null)
            {
                string[] actionList = Regex.Split(actionString, ",");                
                actions = new ArrayList(actionList);
            }

            Threshold q = new Threshold(eventName, count, interval, actions);
            return q;
        }

        static readonly string ACCESS_CONTROLLER_CLASS = "AccessControllerClass";
        static readonly string ENCODER_CLASS = "EncoderClass";
        static readonly string ENCRYPTOR_CLASS = "EncyptorClass";
        static readonly string HTTP_UTILITIES_CLASS = "HttpUtilitiesClass";
        static readonly string INTRUSION_DETECTOR_CLASS = "IntrusionDetectorClass";
        static readonly string LOGGER_CLASS = "LoggerClass";
        static readonly string RANDOMIZER_CLASS = "RandomizerClass";
        static readonly string VALIDATOR_CLASS = "ValidatorClass";

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.AccessControllerClass" />
        public Type AccessControllerClass
        {
            get
            {
                return Type.GetType(properties[ACCESS_CONTROLLER_CLASS]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.EncoderClass" />
        public Type EncoderClass
        {
            get
            {
                return Type.GetType(properties[ENCODER_CLASS]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.EncryptorClass" />
        public Type EncryptorClass
        {
            get
            {
                return Type.GetType(properties[ENCRYPTOR_CLASS]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.HttpUtilitiesClass" />
        public Type HttpUtilitiesClass
        {
            get
            {
                return Type.GetType(properties[HTTP_UTILITIES_CLASS]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.IntrusionDetectorClass" />
        public Type IntrusionDetectorClass
        {
            get
            {
                return Type.GetType(properties[INTRUSION_DETECTOR_CLASS]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.LoggerClass" />
        public Type LoggerClass
        {
            get
            {
                return Type.GetType(properties[LOGGER_CLASS]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.RandomizerClass" />
        public Type RandomizerClass
        {
            get
            {
                return Type.GetType(properties[RANDOMIZER_CLASS]);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.ValidatorClass" />
        public Type ValidatorClass
        {
            get
            {
                return Type.GetType(properties[VALIDATOR_CLASS]);
            }
        }
    }
}
