/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/.NET_ESAPI.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IEncryptedProperties interface is a properties file where all the data is
    /// encrypted before it is added, and decrypted when it retrieved.
    /// [P]
    /// [img src="doc-files/EncryptedProperties.jpg" height="600">
    /// [P]
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    public interface IEncryptedProperties
    {

        /// <summary> Gets the property value from the encrypted store, decrypts it, and returns the 
        /// plaintext value to the caller.
        /// </summary>
        /// <param name="key">The key for the property key/value pair.
        /// </param>
        /// <returns> The property (decrypted).
        /// </returns>
        string GetProperty(string key);

        /// <summary> Encrypts the plaintext property value and stores the ciphertext value in the encrypted store.        
        /// </summary>
        /// <param name="key">The key for the property key/value pair.
        /// </param>
        /// <param name="value">The value to set the property to.
        /// </param>
        /// <returns> The value the property was set to.
        /// </returns>
        string SetProperty(string key, string value);
    }
}
