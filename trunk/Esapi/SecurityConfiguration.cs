/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/.NET_ESAPI.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using System.IO;
using Owasp.Esapi.Interfaces;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Specialized;
using System.Text;

namespace Owasp.Esapi
{
    /// <summary> The SecurityConfiguration manages all the settings used by the ESAPI in a single place. Initializing the
    /// Configuration is critically important to getting the ESAPI working properly.
    /// 
    /// You must have the relevant configuration in your config file (app.config, web.config).
    /// 
    /// See the app.config file in this package and copy the value over.    
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@founstone.com)
    /// </author>
    /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration">
    /// </seealso>
    /// 
    public class SecurityConfiguration : ISecurityConfiguration
    {

        /// <summary> 
        /// The master password.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.MasterPassword">
        /// </seealso>
        public string MasterPassword
        {
            get
            {
                return properties[MASTER_PASSWORD];
            }
        }

        /// <summary> 
        /// The master salt.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.MasterSalt">
        /// </seealso>
        public byte[] MasterSalt
        {
            get
            {
                return new ASCIIEncoding().GetBytes(MASTER_SALT);
            }

        }

        /// <summary> 
        /// The allowed file extensions.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.AllowedFileExtensions">
        /// </seealso>
        public IList AllowedFileExtensions
        {
            get
            {
                string def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
                string[] extList = Regex.Split((properties[VALID_EXTENSIONS] == null ? def : properties[VALID_EXTENSIONS]), ",");
                return new ArrayList(extList);
            }

        }
        
        /// <summary> 
        /// The allowed file upload size.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.AllowedFileUploadSize">
        /// </seealso>
        public int AllowedFileUploadSize
        {
            get
            {
                string bytes = properties[MAX_UPLOAD_FILE_BYTES] == null ? "50000" : properties[MAX_UPLOAD_FILE_BYTES];
                return Int32.Parse(bytes);
            }

        }

        /// <summary> 
        /// The encryption algorithm.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.EncryptionAlgorithm">
        /// </seealso>
        public string EncryptionAlgorithm
        {
            get
            {
                return properties[ENCRYPTION_ALGORITHM];
            }

        }
        /// <summary> 
        /// The hasing algorithm.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.HashAlgorithm">
        /// </seealso>
        public string HashAlgorithm
        {
            get
            {
                return properties[HASH_ALGORITHM];
            }

        }
        /// <summary> 
        /// The character encoding.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.CharacterEncoding">
        /// </seealso>
        public string CharacterEncoding
        {
            get
            {
                return properties[CHARACTER_ENCODING];
            }

        }
        /// <summary> 
        /// The digital signature algorithm.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.DigitalSignatureAlgorithm">
        /// </seealso>
        public string DigitalSignatureAlgorithm
        {
            get
            {
                return properties[DIGITAL_SIGNATURE_ALGORITHM];
            }

        }
        /// <summary> 
        /// The random number generation algorithm.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.RandomAlgorithm">
        /// </seealso>
        public string RandomAlgorithm
        {
            get
            {
                return properties[RANDOM_ALGORITHM];
            }

        }

        /// <summary>
        /// This value determines what level will be used for logging.
        /// </summary>
        public int LogLevel
        {
            get
            {
                string level = properties.Get(LOG_LEVEL);
                if (level == null)
                {
                    // TODO: Do something here
                }
                return LogLevels.ParseLogLevel(level);
            }
        }

        /// <summary>
        /// This value is the response content type that will be used.
        /// </summary>        
        public string ResponseContentType
        {
            get
            {
                string def = "text/html; charset=UTF-8";
                return properties[RESPONSE_CONTENT_TYPE] == null ? def : properties[RESPONSE_CONTENT_TYPE];
            }
        }

        /// <summary>
        /// The names of validation patterns loaded.
        /// </summary>
        public IEnumerator ValidationPatternNames
        {
            get
            {
                ArrayList list = new ArrayList();
                IEnumerator i = properties.GetEnumerator();                             
                while (i.MoveNext())
                {                    
                    string name = (string)i.Current;
                    if (name.StartsWith("Validator."))
                    {
                        list.Add(name.Substring(name.IndexOf('.') + 1));
                    }
                }
                return list.GetEnumerator();
            }
        }

        /// <summary>
        /// If true, values in the log should be encoded.
        /// </summary>
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

        /// <summary>Regular expression cache </summary>
        private IDictionary regexMap = null;

        /// <summary>The logger. </summary>                
        private static readonly ILogger logger;

        /// <summary>
        /// The key for the resources directory property.
        /// </summary>
        public const string RESOURCE_DIRECTORY = "Owasp.Esapi.resources";

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
                
        /// <summary> The directory for resources.
        /// </summary>        
        private static string resourceDirectory;

        /// <summary> Instantiates a new configuration.</summary>
        public SecurityConfiguration()
        {
            // FIXME : this should be reloaded periodically
            LoadConfiguration();
        }

        /// <summary> Loads the configuration.</summary>        
        private void LoadConfiguration()
        {
            properties = (NameValueCollection)System.Configuration.ConfigurationManager.GetSection("esapi");
            resourceDirectory = properties.Get("ResourceDirectory");
            Console.WriteLine("Loaded ESAPI properties from espai/authentication");
            
            IEnumerator i = properties.GetEnumerator();            
            while (i.MoveNext())
            {                
                string key = (string)i.Current;
                Console.WriteLine("  |   " + key + "=" + properties[(string)key]);
            }
            
            // cache regular expressions            
            regexMap = new Hashtable();

            IEnumerator regexIterator = ValidationPatternNames;            
            while (regexIterator.MoveNext())
            {
                string name = (string)regexIterator.Current;
                Regex regex = GetValidationPattern(name);
                if (name != null && regex != null)
                {
                    regexMap[name] = regex;
                }
            }
        }

        // FIXME: ENHANCE should read these quotas into a map and cache them
        /// <summary> 
        /// The intrusion detection quota for a particular events.
        /// </summary>
        /// <param name="eventName">
        /// The quote for a particular event name.
        /// </param>
        /// <returns> The threshold for the event.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.GetQuota(string)">
        /// </seealso>
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

        /// <summary>
        /// Gets the validation pattern for a particular type of validation.
        /// </summary>
        /// <param name="key">The type of data to validate.</param>
        /// <returns>The regular expression to validate the data against.</returns>
        public Regex GetValidationPattern(string key)
        {
            string validatorValue = properties.Get("Validator." + key);
            if (validatorValue == null)
                return null;
            Regex regex = new Regex(validatorValue);
            return regex;
        }

        static readonly string ENCODER_CLASS = "EncoderClass";
        static readonly string ENCRYPTOR_CLASS = "EncyptorClass";
        static readonly string INTRUSION_DETECTOR_CLASS = "IntrusionDetectorClass";
        static readonly string LOGGER_CLASS = "LoggerClass";
        static readonly string RANDOMIZER_CLASS = "RandomizerClass";
        static readonly string VALIDATOR_CLASS = "ValidatorClass";

        public Type EncoderClass
        {
            get
            {
                return Type.GetType(properties[ENCODER_CLASS]);
            }
        }

        public Type EncryptorClass
        {
            get
            {
                return Type.GetType(properties[ENCRYPTOR_CLASS]);
            }
        }

        public Type IntrusionDetectorClass
        {
            get
            {
                return Type.GetType(properties[INTRUSION_DETECTOR_CLASS]);
            }
        }

        public Type LoggerClass
        {
            get
            {
                return Type.GetType(properties[LOGGER_CLASS]);
            }
        }

        public Type RandomizerClass
        {
            get
            {
                return Type.GetType(properties[RANDOMIZER_CLASS]);
            }
        }

        public Type ValidatorClass
        {
            get
            {
                return Type.GetType(properties[VALIDATOR_CLASS]);
            }
        }


        
        /// <summary>
        /// Static constructor
        /// </summary>
        static SecurityConfiguration()
        {           
            logger = Esapi.Logger;
        }
    }
}
