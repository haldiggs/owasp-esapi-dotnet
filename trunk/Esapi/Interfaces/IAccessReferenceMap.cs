using System;
using System.Collections;

namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// The AccessReferenceMap interface is used to map from a set of internal direct object references to a 
    /// set of indirect references that are safe to disclose publicly. This can be used to help protect database 
    /// keys, filenames, and other types of direct object references. As a rule, developers should not expose 
    /// their direct object references as it enables attackers to  attempt to manipulate them. 
    ///  
    /// Indirect references are handled as strings, to facilitate their use in HTML. Implementations can generate 
    /// simple integers or more complicated random  character strings as indirect references. Implementations
    /// should probably add a constructor that takes a list of direct references. 
    /// 
    /// Note that in addition to defeating all forms of parameter tampering attacks, here is a side benefit of the 
    /// IAccessReferenceMap. Using random strings as indirect object references, as opposed to simple integers makes
    /// it impossible for an attacker to guess valid identifiers. So if per-user AccessReferenceMaps are used, 
    /// then request forgery (CSRF) attacks will also be prevented. 
    /// </summary>
    interface IAccessReferenceMap
    {
        /// <summary> 
        /// Get a safe indirect reference to use in place of a potentially sensitive
        /// direct object reference. Developers should use this call when building
        /// URL's, form fields, hidden fields, etc... to help protect their private
        /// implementation information.
        /// </summary>
        /// <param name="directReference">The direct reference.</param>
        /// <returns> The indirect reference.</returns>
        String GetIndirectReference(Object directReference);

        /// <summary> 
        /// Get the original direct object reference from an indirect reference.
        /// Developers should use this when they get an indirect reference from an
        /// HTTP request to translate it back into the real direct reference. If an
        /// invalid indirectReference is requested, then an AccessControlException is
        /// thrown.
        /// </summary>
        /// <param name="indirectReference">The indirect reference.</param>
        /// <returns> The direct reference.</returns>
        Object GetDirectReference(String indirectReference);

        /// <summary> Returns a collection of the indirect object references.</summary>
        /// <returns> The collection of indirect object references.</returns>        
        ICollection GetIndirectReferences();

        /// <summary> Returns a collection of the direct object references.</summary>
        /// <returns> The collection of direct object references.</returns>
		ICollection GetDirectReferences();

        /// <summary> Adds a direct reference and a new random indirect reference, overwriting any existing values.</summary>
        /// <param name="direct"> The direct reference to add.</param>
        String AddDirectReference(Object direct);
        
        /// <summary> Remove a direct reference and the corresponding indirect reference.</summary>
        /// <param name="direct">The direct reference.</param>
        String RemoveDirectReference(Object direct);
        
        /// <summary> 
        /// Update the refrences. This preserves any existing mappings for items that are still in the new
        /// list. You could regenerate new indirect references every time, but that might break anything 
        /// that previously used an indirect reference, such as a URL parameter.
        /// </summary>
        /// <param name="directReferences">The direct references.</param>
        void Update(ICollection directReferences);
    }
}
