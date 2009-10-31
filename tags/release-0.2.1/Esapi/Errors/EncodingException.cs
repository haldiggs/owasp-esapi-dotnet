using System;

namespace Owasp.Esapi.Errors
{
    /// <summary> An ExecutorException should be thrown for any problems that occur when
    /// encoding or decoding data.    
    /// </summary>
    [Serializable]
    public class EncodingException : EnterpriseSecurityException
    {
        /// <summary> Instantiates a new service exception.</summary>
        protected internal EncodingException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of EncodingException.
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        public EncodingException(string userMessage, string logMessage)
            : base(userMessage, logMessage)
        {
        }

        /// <summary> Instantiates a new EncodingException.
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause of the exception.
        /// </param>        
        public EncodingException(string userMessage, string logMessage, Exception cause)
            : base(userMessage, logMessage, cause)
        {
        }

    }
}
