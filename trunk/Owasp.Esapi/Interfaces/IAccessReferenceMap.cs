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
using System.Collections;

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IAccessReferenceMap interface is used to map from a set of internal
    /// direct object references to a set of indirect references that are safe to
    /// disclose publically. This can be used to help protect database keys,
    /// filenames, and other types of direct object references. As a rule, developers
    /// should not expose their direct object references as it enables attackers to
    /// attempt to manipulate them.
    ///
    /// If you use an AccessReferenceMap that generates random strings on a per-user
    /// basis, the indirect references may have the beneficial side-effect of
    /// preventing Cross-Site Request Forgery (CSRF) attacks. Because an attacker
    /// cannot know the right values to provide to match real direct references, they
    /// will not be able to forge requests.
    /// 
    /// Indirect references are handled as strings, to facilitate their use in HTML.
    /// Implementations can generate simple integers or more complicated random
    /// character strings as indirect references. Implementations should probably add
    /// a constructor that takes a list of direct references.
    /// 
    /// Set fileSet = new HashSet();
    /// fileSet.addAll(...);
    /// AccessReferenceMap map = new AccessReferenceMap( fileSet );
    /// // store the map somewhere safe - like the session!
    /// String indRef = map.getIndirectReference( file1 );
    /// String href = &quot;http://www.aspectsecurity.com/esapi?file=&quot; + indRef );
    /// ...
    /// String indref = request.getParameter( &quot;file&quot; );
    /// File file = (File)map.getDirectReference( indref );
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    public interface IAccessReferenceMap
    {
        /// <summary> Get an enumerator through the direct object references.
        /// 
        /// </summary>
        /// <returns> The enumerator through the direct object referneces.
        /// </returns>
        IEnumerator Enumerator();

        /// <summary> Get a safe indirect reference to use in place of a potentially sensitive
        /// direct object reference. Developers should use this call when building
        /// URL's, form fields, hidden fields, etc... to help protect their private
        /// implementation information.
        /// 
        /// </summary>
        /// <param name="directReference">The direct reference.
        /// 
        /// </param>
        /// <returns> The indirect reference.
        /// </returns>
        string GetIndirectReference(Object directReference);

        /// <summary> Get the original direct object reference from an indirect reference.
        /// Developers should use this when they get an indirect reference from an
        /// HTTP request to translate it back into the real direct reference. If an
        /// invalid indirectReference is requested, then an AccessControlException is
        /// thrown.
        /// 
        /// </summary>
        /// <param name="indirectReference">The indirect reference.
        /// 
        /// </param>
        /// <returns> The direct reference.
        /// 
        /// </returns>
        Object GetDirectReference(string indirectReference);
    }
}
