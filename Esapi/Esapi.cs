using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <summary>
    /// This class provides accessor methods for the various ESAPI implementations.
    /// </summary>
    public class Esapi
    {
        private static IAccessController accessController;        
        
        private static IEncoder encoder;

        private static IEncryptor encryptor;
        
        private static IHttpUtilities httpUtilities;

        private static IIntrusionDetector intrusionDetector;

        private static IRandomizer randomizer;

        private static ISecurityConfiguration securityConfiguration;

        private static IValidator validator;

        /// <summary>
        /// The IAccessController implementation.
        /// </summary>
        public static IAccessController AccessController
        {
            set
            {
                accessController = value;
            }

            get
            {
                if (accessController == null)
                {
                    accessController = (IAccessController)Activator.CreateInstance(Esapi.SecurityConfiguration.AccessControllerClass);
                }
                return accessController;
            }
        }


        /// <summary>
        /// The IEncoder implementation.
        /// </summary>
        public static IEncoder Encoder
        {
            set
            {
                encoder = value;
            }

            get
            {
                if (encoder == null)
                {
                    encoder = (IEncoder) Activator.CreateInstance(Esapi.SecurityConfiguration.EncoderClass);
                }
                return encoder;                
            }
        }
        
        /// <summary>
        /// The IEncryptor implementation.
        /// </summary>
        public static IEncryptor Encryptor
        {
            set
            {
                encryptor = value;
            }
            get
            {
                if (encryptor == null)
                {
                    encryptor = (IEncryptor)Activator.CreateInstance(Esapi.SecurityConfiguration.EncryptorClass);
                }
                return encryptor;                
            }
        }

        /// <summary>
        /// The IHttpUtilties implementation.
        /// </summary>
        public static IHttpUtilities HttpUtilities
        {
            set
            {
                httpUtilities = value;
            }
            get
            {
                if (httpUtilities == null)
                {
                    httpUtilities = (IHttpUtilities)Activator.CreateInstance(Esapi.SecurityConfiguration.HttpUtilitiesClass);
                }
                return httpUtilities;
            }
        }

        /// <summary>
        /// The IIntrusionDetector implementation.
        /// </summary>
        public static IIntrusionDetector IntrusionDetector
        {
            set
            {
                intrusionDetector = value;
            }
            get
            {
                if (intrusionDetector == null)
                {
                    intrusionDetector =  (IIntrusionDetector)Activator.CreateInstance(Esapi.SecurityConfiguration.IntrusionDetectorClass);
                }
                return intrusionDetector;               
            }
        }

        /// <summary>
        /// The IRandomizer implementation.
        /// </summary>
        public static IRandomizer Randomizer
        {
            set
            {
                randomizer = value;
            }
            get
            {
                if (randomizer == null)
                {
                    randomizer =  (IRandomizer)Activator.CreateInstance(Esapi.SecurityConfiguration.RandomizerClass);
                }
                return randomizer;         
            }
        }

        /// <summary>
        /// The IValidator implementation.
        /// </summary>
        public static IValidator Validator
        {
            set
            {
                validator = value;
            }

            get
            {
                if (validator == null)
                {
                    validator = (IValidator)Activator.CreateInstance(Esapi.SecurityConfiguration.ValidatorClass);
                }
                return validator;
            }
        }

        /// <summary>
        /// The ISecurityConfiguration implementation.
        /// </summary>
        public static ISecurityConfiguration SecurityConfiguration
        {
            set
            {
                securityConfiguration = value;
            }
            get
            {
                if (securityConfiguration == null)
                {
                    securityConfiguration = new SecurityConfiguration();
                }
                return securityConfiguration;
            }
        }

        /// <summary>
        /// The ILogger implementation.
        /// </summary>
        public static ILogger Logger
        {
            get
            {
                return new Logger("Owasp.Esapi");
            }
        }


        /// <summary>
        /// Gets a specific logger for a different class name.
        /// </summary>
        /// <param name="className">The class name to get the logger for.</param>
        /// <returns>The logger associated with the class name.</returns>
        public static ILogger GetLogger(string className)
        {
            return new Logger(className);
        }
       
        /// <summary>Prevent instantiation of this class.</summary>
        private Esapi()
        {
        }        
    }        	
}