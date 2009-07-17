using System;

namespace Owasp.Esapi.Errors
{
    /// <summary> An IntegrityException should be thrown when a problem with the integrity of data 
    /// has been detected. For example, if a financial account cannot be reconciled after 
    /// a transaction has been performed, an integrity exception should be thrown. 
    /// </summary>
    [Serializable]
    public class IntegrityException: EnterpriseSecurityException
    {

        /// <summary> Instantiates a new integrity exception.</summary>
        protected internal IntegrityException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of IntegrityException.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        public IntegrityException(string userMessage, string logMessage)
            : base(userMessage, logMessage)
        {
        }

        /// <summary> Instantiates a new IntegrityException.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause of the exception.
        /// </param>
        public IntegrityException(string userMessage, string logMessage, Exception cause)
            : base(userMessage, logMessage, cause)
        {
        }
    }
}
