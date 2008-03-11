/// <summary> OWASP Enterprise Security API .NET (ESAPI.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;

namespace Owasp.Esapi.Errors
{

    /// <summary> An IntrusionException should be thrown anytime an error condition arises that is likely to be the result of an attack
    /// in progress. IntrusionExceptions are handled specially by the IntrusionDetector, which is equipped to respond by
    /// either specially logging the event, logging out the current user, or invalidating the current user's account.
    /// [P]
    /// Unlike other exceptions in the ESAPI, the IntrusionException is a RuntimeException so that it can be thrown from
    /// anywhere and will not require a lot of special exception handling.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [Serializable]
    public class IntrusionException : SystemException
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

        /// <summary>The Constant serialVersionUID. </summary>
        private const long _serialVersionUID = 1L;

        /// <summary>The logger. </summary>
        protected internal static readonly Logger _logger;
        
        /// <summary>
        ///  The message for the log
        /// </summary>
        protected internal string _logMessage = null;

        /// <summary> Internal classes may throw an IntrusionException to the IntrusionDetector, which generates the appropriate log
        /// message.
        /// </summary>
        public IntrusionException()
            : base()
        {
        }

        /// <summary> Creates a new instance of IntrusionException.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        public IntrusionException(string userMessage, string logMessage)
            : base(userMessage)
        {
            this._logMessage = logMessage;
            _logger.LogError(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "INTRUSION - " + logMessage);
        }

        /// <summary> Instantiates a new intrusion exception.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause of the exception.
        /// </param>        
        public IntrusionException(string userMessage, string logMessage, System.Exception cause)
            : base(userMessage, cause)
        {
            this._logMessage = logMessage;
            _logger.LogError(Owasp.Esapi.Interfaces.ILogger_Fields.SECURITY, "INTRUSION - " + logMessage, cause);
        }
        static IntrusionException()
        {
            _logger = Logger.GetLogger("ESAPI", "IntrusionException");
        }
    }
}
