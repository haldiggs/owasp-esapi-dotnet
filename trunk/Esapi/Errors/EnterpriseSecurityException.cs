using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Errors
{
    /// <summary>
    /// EnterpriseSecurityException is the base class for all security related exceptions. You should pass in the root cause
    /// exception where possible. Constructors for classes extending EnterpriseSecurityException should be sure to call the
    /// appropriate base constructor in order to ensure that logging and intrusion detection occur properly.   
    /// </summary>
    [Serializable]
    public class EnterpriseSecurityException : Exception
    {
        /// <summary>
        /// The message for the user
        /// </summary>
        virtual public string UserMessage
        {
            get
            {                
                return Message;
            }

        }
        /// <summary>
        /// The message for the log
        /// </summary>
        virtual public string LogMessage
        {
            get
            {
                return _logMessage;
            }

        }

        /// <summary>The logger. </summary>
        private static readonly ILogger logger;

        /// <summary>The message for the log. </summary>
        private string _logMessage = null;

        /// <summary> Instantiates a new security exception.</summary>
        protected internal EnterpriseSecurityException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of EnterpriseSecurityException. This exception is automatically logged, so that simply by
        /// using this API, applications will generate an extensive security log. In addition, this exception is
        /// automatically registrered with the IntrusionDetector, so that quotas can be checked.
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        public EnterpriseSecurityException(string userMessage, string logMessage)
            : base(userMessage)
        {
            this._logMessage = logMessage;
            Esapi.IntrusionDetector.AddException(this);
        }

        /// <summary> Creates a new instance of EnterpriseSecurityException that includes a root cause Throwable.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause of the exception.
        /// </param>        
        public EnterpriseSecurityException(string userMessage, string logMessage, System.Exception cause)
            : base(userMessage, cause)
        {
            this._logMessage = logMessage;
            Esapi.IntrusionDetector.AddException(this);
        }

        static EnterpriseSecurityException()
        {
            logger = Esapi.Logger;
        }
    }
}
