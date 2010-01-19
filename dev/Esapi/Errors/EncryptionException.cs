using System;

namespace Owasp.Esapi.Errors
{
    /// <summary> An EncryptionException should be thrown for any problems related to
    /// encryption, hashing, or digital signatures.
    /// </summary>
    [Serializable]
    public class EncryptionException : EnterpriseSecurityException
    {
        /// <summary> Instantiates a new EncryptionException.</summary>
        protected internal EncryptionException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of EncryptionException.
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        public EncryptionException(string userMessage, string logMessage)
            : base(userMessage, logMessage)
        {
        }

        /// <summary> Instantiates a new EncryptionException.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause of the exception.
        /// </param>        
        public EncryptionException(string userMessage, string logMessage, Exception cause)
            : base(userMessage, logMessage, cause)
        {
        }
    }
}
