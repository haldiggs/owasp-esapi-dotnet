/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/Category:ESAPI.
/// 
/// Copyright (c) 2009 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the BSD. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen
/// </author>
/// <created>  2008 </created>

using System;

namespace Owasp.Esapi.Errors
{
    /// <summary> A ValidationException should be thrown to indicate that the data provided by
    /// the user or from some other external source does not match the validation
    /// rules that have been specified for that data.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (me@alexsmolen.com)
    /// </author>
    [Serializable]
    public class ValidationException : EnterpriseSecurityException
    {

        /// <summary>The Constant serialVersionUID. </summary>
        private const long _serialVersionUID = 1L;

        /// <summary> Instantiates a new validation exception.</summary>
        protected internal ValidationException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of ValidationException.
        /// 
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
        /// 
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
