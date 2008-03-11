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

    /// <summary> An EncryptionException should be thrown for any problems related to
    /// encryption, hashing, or digital signatures.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [Serializable]
    public class EncryptionException : EnterpriseSecurityException
    {

        /// <summary>The Constant _serialVersionUID. </summary>
        private const long _serialVersionUID = 1L;

        /// <summary> Instantiates a new EncryptionException.</summary>
        protected internal EncryptionException()
        {
            // hidden
        }

        /// <summary> Creates a new instance of EncryptionException.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        public EncryptionException(string userMessage, string logMessage)
            : base(userMessage, logMessage)
        {
        }

        /// <summary> Instantiates a new EncryptionException.
        /// 
        /// </summary>
        /// <param name="userMessage">The message for the user.
        /// </param>
        /// <param name="logMessage">The message for the log.
        /// </param>
        /// <param name="cause">The cause of the exception.
        /// </param>        
        public EncryptionException(string userMessage, string logMessage, Exception cause)
            : base(userMessage, logMessage, cause)
        {
        }
    }
}
