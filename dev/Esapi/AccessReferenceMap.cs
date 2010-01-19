using System;
using System.Collections;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using System.Collections.Generic;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap"/>
    /// <summary>
    /// Reference <see cref="Owasp.Esapi.Interfaces.IAccessReferenceMap"/> implementation uses short random strings to
    /// create a layer of indirection. Other possible implementations would use
    /// simple integers as indirect references.
    /// </summary>
    public class AccessReferenceMap : IAccessReferenceMap
    {
        private Dictionary<string, object> itod = new Dictionary<string, object>();
        private Dictionary<object, string> dtoi = new Dictionary<object, string>();

        private IRandomizer random = Esapi.Randomizer;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public AccessReferenceMap()
        {

        }

        /// <summary>
        /// Constructor that accepts collection of direct references.
        /// </summary>
        /// <param name="directReferences">
        /// The collection of direct references to initialize the access reference map.
        /// </param>		
        public AccessReferenceMap(ICollection directReferences)
        {
            Update(directReferences);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetDirectReferences()"/>
        public ICollection GetDirectReferences()
        {
            return dtoi.Keys;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetIndirectReferences()"/>
        public ICollection GetIndirectReferences()
        {
            return itod.Keys;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.AddDirectReference(object)"/>
        public string AddDirectReference(object direct)
        {
            if (direct == null) {
                throw new ArgumentNullException("direct");
            }

            string indirect = random.GetRandomString(6, CharSetValues.Alphanumerics);
            itod[indirect] = direct;
            dtoi[direct] = indirect;
            return indirect;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.RemoveDirectReference(object)"/>	
        public string RemoveDirectReference(object direct)
        {
            if (direct == null) {
                throw new ArgumentNullException("direct");
            }

            string indirect = dtoi[direct];
            if (indirect != null)
            {
                itod.Remove(indirect);
                dtoi.Remove(direct);
            }
            return indirect;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.Update(ICollection)"/>
        public void Update(ICollection directReferences)
        {
            if (directReferences == null) {
                throw new ArgumentNullException("directReferences");
            }

            // Avoid making copies / deletions, collect new records then update current
            Dictionary<object, string> dtoi_new = new Dictionary<object, string>();
            Dictionary<string, object> itod_new = new Dictionary<string, object>();

            foreach (object direct in directReferences)
            {
                // get the old indirect reference
                string indirect;

                if (!dtoi.TryGetValue(direct, out indirect) || indirect == null)
                {
                    // if the old reference is null, then create a new one that doesn't
                    // collide with any existing indirect references
                    do
                    {
                        indirect = random.GetRandomString(6, CharSetValues.Alphanumerics);
                    }
                    while (itod_new.ContainsKey(indirect));
                }

                itod_new[indirect] = direct;
                dtoi_new[direct] = indirect;
            }

            itod = itod_new;
            dtoi = dtoi_new;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetIndirectReference(object)"/>
        public string GetIndirectReference(Object directReference)
        {
            if (directReference == null) {
                throw new ArgumentNullException("directReference");
            }

            string indirect;
            dtoi.TryGetValue(directReference, out indirect);

            return indirect;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetDirectReference(string)"/>
        public object GetDirectReference(string indirectReference)
        {
            if (indirectReference == null) {
                throw new ArgumentNullException("indirectReference");
            }

            if (!itod.ContainsKey(indirectReference)) {
                throw new AccessControlException(EM.AccessReferenceMap_AccessDeniedUser, 
                                EM.AccessReferenceMap_AccessDeniedLog);
            }

            return itod[indirectReference];
        }
    }
}
