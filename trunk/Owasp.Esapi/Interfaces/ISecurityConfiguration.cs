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
/// <author>  Alex Smolen [a href="http://www.foundstone.com"]Foundstone[/a]
/// </author>
/// <created>  2008 </created>

using System;
using System.IO;
using System.Collections;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The ISecurityConfiguration interface stores all configuration information
    /// that directs the behavior of the ESAPI implementation.
    /// [P]
    /// [img src="doc-files/SecurityConfiguration.jpg" height="600"]
    /// [P]
    /// Protection of this configuration information is critical to the secure
    /// operation of the application using the ESAPI. You should use operating system
    /// access controls to limit access to wherever the configuration information is
    /// stored. Please note that adding another layer of encryption does not make the
    /// attackers job much more difficult. Somewhere there must be a master "secret"
    /// that is stored unencrypted on the application platform. Creating another
    /// layer of indirection doesn't provide any real additional security.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>

    public interface ISecurityConfiguration
    {
        /// <summary> 
        /// The master password.
        /// </summary>
        string MasterPassword
        {
            get;

        }

        // Note: Don't think we need this in .NET.
        /// <summary> 
        /// The keystore.        
        /// </summary>
        FileInfo Keystore
        {
            get;

        }
        /// <summary> 
        /// The master salt.        
        /// </summary>        
        byte[] MasterSalt
        {
            get;

        }
        /// <summary> 
        /// The allowed file extensions.        
        /// </summary>
        IList AllowedFileExtensions
        {
            get;

        }
        /// <summary> 
        /// The allowed file upload size.        
        /// </summary>
        int AllowedFileUploadSize
        {
            get;

        }
        /// <summary> 
        /// The password parameter name.        
        /// </summary>
        string PasswordParameterName
        {
            get;

        }
        /// <summary> 
        /// The username parameter name.        
        /// </summary>
        string UsernameParameterName
        {
            get;

        }

        /// <summary> 
        /// The encryption algorithm.        
        /// </summary>
        string EncryptionAlgorithm
        {
            get;

        }
        /// <summary> 
        /// The hasing algorithm.        
        /// </summary>
        string HashAlgorithm
        {
            get;

        }
        /// <summary> 
        /// The character encoding.        
        /// </summary>
        string CharacterEncoding
        {
            get;

        }
        /// <summary> 
        /// The digital signature algorithm.        
        /// </summary>
        string DigitalSignatureAlgorithm
        {
            get;

        }
        /// <summary> 
        /// The random number generation algorithm.
        /// </summary>
        string RandomAlgorithm
        {
            get;

        }
        /// <summary> 
        /// The allowed login attempts.        
        /// </summary>
        int AllowedLoginAttempts
        {
            get;

        }
        /// <summary> 
        /// The max old password hashes.        
        /// </summary>
        int MaxOldPasswordHashes
        {
            get;

        }

        FileInfo ResourceDirectory
        {
            get;
            set;
        }

        bool RequireSecureChannel
        {
            get;
        }

        /// <summary> 
        /// The intrusion detection quota for a particular events.
        /// </summary>
        /// <param name="eventName">
        /// The quote for a particular event name.
        /// </param>
        /// <returns> The threshold for the event.
        /// </returns>
        Threshold GetQuota(string eventName);        
    
    }
}
