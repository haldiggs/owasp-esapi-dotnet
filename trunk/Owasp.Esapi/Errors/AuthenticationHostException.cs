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
    /// <summary> An AuthenticationHostException should be thrown when there is a problem with
    /// the host involved with authentication, particularly if the host changes unexpectedly.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [Serializable]
    public class AuthenticationHostException: AuthenticationException
    {
        /// <summary>The Constant serialVersionUID. </summary>
        private const long serialVersionUID = 1L;

        /// <summary> Instantiates a new authentication exception.</summary>
        protected internal AuthenticationHostException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of AuthenticationHostException.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The log message.
        /// </param>
        public AuthenticationHostException(string userMessage, string logMessage)
            : base(userMessage, logMessage)
        {
        }

        /// <summary> Instantiates a new authentication exception.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The log message.
        /// </param>
        /// <param name="cause">The cause.
        /// </param>        
        public AuthenticationHostException(string userMessage, string logMessage, Exception cause)
            : base(userMessage, logMessage, cause)
        {
        }
    }

}
