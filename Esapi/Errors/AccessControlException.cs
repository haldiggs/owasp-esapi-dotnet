using System;

namespace Owasp.Esapi.Errors
{
    /// <summary> 
    /// An AccessControlException should be thrown when a user attempts to access a
    /// resource that they are not authorized for.
    /// </summary>
    [Serializable]
    public class AccessControlException : EnterpriseSecurityException
    {

        /// <summary> Instantiates a new access control exception.</summary>
        protected internal AccessControlException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of EnterpriseSecurityException.</summary>
        public AccessControlException(string userMessage, string logMessage)
            : base(userMessage, logMessage)
        {
        }

        /// <summary>Instantiates a new access control exception.
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause.
        /// </param>        
        public AccessControlException(string userMessage, string logMessage, Exception cause)
            : base(userMessage, logMessage, cause)
        {
        }
    }
}
