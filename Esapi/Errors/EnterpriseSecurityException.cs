using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Errors
{

    /// <summary> EnterpriseSecurityException is the base class for all security related exceptions. You should pass in the root cause
    /// exception where possible. Constructors for classes extending EnterpriseSecurityException should be sure to call the
    /// appropriate super() method in order to ensure that logging and intrusion detection occur properly.
    /// <P>
    /// All EnterpriseSecurityExceptions have two messages, one for the user and one for the log file. This way, a message
    /// can be shown to the user that doesn't contain sensitive information or unnecessary implementation details. Meanwhile,
    /// all the critical information can be included in the exception so that it gets logged.
    /// </P>
    /// <P>
    /// Note that the "LogMessage" for ALL EnterpriseSecurityExceptions is logged in the log file. This feature should be
    /// used extensively throughout ESAPI implementations and the result is a fairly complete set of security log records.
    /// ALL EnterpriseSecurityExceptions are also sent to the IntrusionDetector for use in detecting anomolous patterns of
    /// application usage.
    /// </P>
    /// </summary>
    [Serializable]
    public class EnterpriseSecurityException : System.Exception
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
        protected internal static readonly ILogger logger;

        /// <summary>The message for the log. </summary>
        protected internal string _logMessage = null;

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
