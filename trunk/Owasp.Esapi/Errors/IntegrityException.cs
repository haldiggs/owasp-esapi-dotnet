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
    /// <summary> An AvailabilityException should be thrown when the availability of a limited
    /// resource is in jeopardy. For example, if a database connection pool runs out
    /// of connections, an availability exception should be thrown.
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [Serializable]
    public class IntegrityException: EnterpriseSecurityException
    {
        /// <summary>The Constant serialVersionUID. </summary>
        private const long serialVersionUID = 1L;

        /// <summary> Instantiates a new availability exception.</summary>
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
