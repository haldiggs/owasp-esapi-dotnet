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
using System.Diagnostics;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <summary>
    /// This class provides accessor methods for the various ESAPI implementations.
    /// </summary>
    public class Esapi
    {

        //private static IAccessController accessController = null;

        private static IEncoder encoder = null;

        private static IEncryptor encryptor = null;

        //private static IExecutor executor = null;

        //private static IHttpUtilities httpUtilities = null;

        private static IIntrusionDetector intrusionDetector = null;

        private static IRandomizer randomizer = null;

        private static ISecurityConfiguration securityConfiguration = null;

        private static IValidator validator = null;

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
        ///// <param name="encryptor">the encryptor to set
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
        ///// <param name="executor">the executor to set
        ///// </param>
        //public static IExecutor Executor
        //{
        //    set
        //    {
        //        Esapi.executor = value;
        //    }

        //}
        ///// <param name="httpUtilities">the httpUtilities to set
        ///// </param>
        //public static IHttpUtilities HttpUtilities
        //{
        //    set
        //    {
        //        Esapi.httpUtilities = value;
        //    }

        //}

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
                    validator = (IValidator) Activator.CreateInstance(Esapi.SecurityConfiguration.ValidatorClass);
                }
                return validator;                
            }
        }

        ///// <summary> prevent instantiation of this class</summary>
        private Esapi()
        {
        }        
    }        	
}