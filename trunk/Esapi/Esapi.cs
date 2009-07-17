using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <summary>
    /// This class provides accessor methods for the various ESAPI implementations.
    /// </summary>
    public class Esapi
    {
        private static IAccessController accessController = null;        
        
        private static IEncoder encoder = null;

        private static IEncryptor encryptor = null;
        
        private static IHttpUtilities httpUtilities = null;

        private static IIntrusionDetector intrusionDetector = null;

        private static IRandomizer randomizer = null;

        private static ISecurityConfiguration securityConfiguration = null;

        private static IValidator validator = null;

        /// <param name="AccessController">The AccessController to set
        /// </param>
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
        

        /// <param name="encoder">The encoder to set
        /// </param>
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
        /// <param name="encryptor">the encryptor to set
        /// </param>
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

        /// <param name="encryptor">the httpUtilities to set
        /// </param>
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

        /// <param name="intrusionDetector">the intrusionDetector to set
        /// </param>
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

        /// <param name="randomizer">the randomizer to set
        /// </param>
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

        /// <param name="validator">the validator to set
        /// </param>
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

        /// <param name="securityConfiguration">the securityConfiguration to set
        /// </param>
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

        public static ILogger Logger
        {
            get
            {
                return new Logger("Owasp.Esapi");
            }
        }


        public static ILogger GetLogger(string className)
        {
            return new Logger(className);
        }
       
        /// <summary> prevent instantiation of this class</summary>
        private Esapi()
        {
        }        
    }        	
}