using System;
using System.Collections;

namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// The IAccessReferenceMap interface is used to map from a set of internal direct object references to a 
    /// set of indirect references that are safe to disclose publicly. This can be used to help protect database 
    /// keys, filenames, and other types of direct object references.
    /// </summary>
    public interface IAccessReferenceMap
    {
        /// <summary> 
        /// Get a safe indirect reference to use in place of a potentially sensitive
        /// direct object reference.
        /// </summary>
        /// <param name="directReference">The direct reference.</param>
        /// <returns> The indirect reference.</returns>
        String GetIndirectReference(Object directReference);

        /// <summary> 
        /// Get the original direct object reference from an indirect reference.
        /// Developers should use this when they get an indirect reference to translate
        /// it back into the real direct reference. If an
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
