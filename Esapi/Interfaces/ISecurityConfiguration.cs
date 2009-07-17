using System;
using System.Collections;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The ISecurityConfiguration interface stores all configuration information
    /// that directs the behavior of the ESAPI implementation.
    /// <img src="doc-files/SecurityConfiguration.jpg" height="600"/>
    /// Protection of this configuration information is critical to the secure
    /// operation of the application using the ESAPI. You should use operating system
    /// access controls to limit access to wherever the configuration information is
    /// stored. Please note that adding another layer of encryption does not make the
    /// attackers job much more difficult. Somewhere there must be a master "secret"
    /// that is stored unencrypted on the application platform. Creating another
    /// layer of indirection doesn't provide any real additional security.    
    /// </summary>
    public interface ISecurityConfiguration
    {
        /// <summary> 
        /// The master password.
        /// </summary>
        string MasterPassword
        {
            get;

        }
    
        /// <summary> 
        /// The master salt.        
        /// </summary>        
        byte[] MasterSalt
        {
            get;
        }

        /// <summary> 
        /// The allowed file extensions.        
        /// </summary>
        IList AllowedFileExtensions
        {
            get;
        }
        
        /// <summary> 
        /// The allowed file upload size.        
        /// </summary>
        int AllowedFileUploadSize
        {
            get;
        }

        /// <summary> 
        /// The encryption algorithm.        
        /// </summary>
        string EncryptionAlgorithm
        {
            get;
        }
        /// <summary> 
        /// The hasing algorithm.        
        /// </summary>
        string HashAlgorithm
        {
            get;
        }
        /// <summary> 
        /// The character encoding.        
        /// </summary>
        string CharacterEncoding
        {
            get;
        }
        /// <summary> 
        /// The digital signature algorithm.        
        /// </summary>
        string DigitalSignatureAlgorithm
        {
            get;
        }
        /// <summary> 
        /// The random number generation algorithm.
        /// </summary>
        string RandomAlgorithm
        {
            get;
        }

        /// <summary>
        /// The log level to use for logging.
        /// </summary>
        int LogLevel
        {
            get;
        }


        /// <summary> 
        /// The intrusion detection quota for a particular events.
        /// </summary>
        /// <param name="eventName">
        /// The quote for a particular event name.
        /// </param>
        /// <returns> The threshold for the event.
        /// </returns>
        Threshold GetQuota(string eventName);

        Type AccessControllerClass
        {
            get;
        }

        Type EncoderClass
        {
            get;
        }

        Type EncryptorClass
        {
            get;
        }

        Type HttpUtilitiesClass
        {
            get;
        }

        Type IntrusionDetectorClass
        {
            get;
        }

        Type LoggerClass
        {
            get;
        }

        Type RandomizerClass
        {
            get;
        }

        Type ValidatorClass
        {
            get;
        }
    }
}
