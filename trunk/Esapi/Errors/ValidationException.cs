using System;

namespace Owasp.Esapi.Errors
{
    /// <summary> A ValidationException should be thrown to indicate that the data provided by
    /// the user or from some other external source does not match the validation
    /// rules that have been specified for that data.
    /// </summary>
    [Serializable]
    public class ValidationException : EnterpriseSecurityException
    {
        /// <summary> Instantiates a new validation exception.</summary>
        protected internal ValidationException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of ValidationException.
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        public ValidationException(string userMessage, string logMessage)
            : base(userMessage, logMessage)
        {
        }

        /// <summary> Instantiates a new ValidationException.
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause of the exception.
        /// </param>     
        public ValidationException(string userMessage, string logMessage, System.Exception cause)
            : base(userMessage, logMessage, cause)
        {
        }
    }
}
