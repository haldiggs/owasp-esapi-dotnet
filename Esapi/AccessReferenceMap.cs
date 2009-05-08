using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Errors;
using System.Collections;

namespace Owasp.Esapi
{
    public class AccessReferenceMap:IAccessReferenceMap
    {    		
		/// <summary>The itod. </summary>		
		internal Hashtable itod = new Hashtable();
		
		/// <summary>The dtoi. </summary>
		internal Hashtable dtoi = new Hashtable();
		
		/// <summary>The random. </summary>		
		internal IRandomizer random = Esapi.Randomizer;
		
		/// <summary> This AccessReferenceMap implementation uses short random strings to
		/// create a layer of indirection. Other possible implementations would use
		/// simple integers as indirect references.
		/// </summary>
		public AccessReferenceMap()
		{
            
		}
		
		/// <summary> Instantiates a new access reference map.
		/// 
		/// </summary>
		/// <param name="directReferences">The direct references.
		/// </param>
		public AccessReferenceMap(IList directReferences)
		{			
			Update(directReferences);
		}

        /// <summary> Get an enumerator through the direct object references.
        /// </summary>
        /// <returns> The enumerator through the direct object referneces.
        /// </returns>        
		public ICollection GetDirectReferences()
		{
			return dtoi.Keys;            
		}



        /// <summary> Get an enumerator through the indirect object references.
        /// </summary>
        /// <returns> The enumerator through the indirect object referneces.
        /// </returns>        
        public ICollection GetIndirectReferences()
        {
            return itod.Keys;
        }

		
		/// <summary> Adds a direct reference and a new random indirect reference, overwriting any existing values.</summary>
		/// <param name="direct">
        ///     The direct reference.
		/// </param>
		public string AddDirectReference(object direct)
		{
			string indirect = random.GetRandomString(6, Encoder.CHAR_ALPHANUMERICS);
			itod[indirect] = direct;
			dtoi[direct] = indirect;
            return indirect;
		}
		
		
		/// <summary> Remove a direct reference and the corresponding indirect reference.</summary>
		/// <param name="direct">
        ///     The direct reference.
		/// </param>
		public string RemoveDirectReference(object direct)
		{			
			string indirect = (string) dtoi[direct];
			if (indirect != null)
			{
				itod.Remove(indirect);
				dtoi.Remove(direct);
			}
            return indirect;
		}
		
		/*
		
		*/
		/// <summary> Update the refrences.
		/// This preserves any existing mappings for items that are still in the new
        /// list. You could regenerate new indirect references every time, but that
        /// might mess up anything that previously used an indirect reference, such
        /// as a URL parameter.
		/// </summary>
		/// <param name="directReferences">The direct references.
		/// </param>
		public void Update(IEnumerable directReferences)
		{			
			Hashtable dtoi_old = (Hashtable) dtoi.Clone();
			dtoi.Clear();
			itod.Clear();
			
			IEnumerator i = directReferences.GetEnumerator();			
			while (i.MoveNext())
			{
				
				object direct = i.Current;
				// get the old indirect reference
				string indirect = (string) dtoi_old[direct];
				
				// if the old reference is null, then create a new one that doesn't
				// collide with any existing indirect references
				if (indirect == null)
				{					
					do 
					{
						indirect = random.GetRandomString(6, Encoder.CHAR_ALPHANUMERICS);
					}
					while (new ArrayList(itod.Keys).Contains(indirect));
				}
				itod[indirect] = direct;
				dtoi[direct] = indirect;
			}
		}

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
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetIndirectReference(object)">
        /// </seealso>
		public string GetIndirectReference(Object directReference)
		{			
			return (string) dtoi[directReference];
		}
		
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
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetDirectReference(string)">
        /// </seealso>
		public object GetDirectReference(string indirectReference)
		{
			
			IEnumerator i = dtoi.GetEnumerator();			
			while (i.MoveNext())
			{				
				DictionaryEntry e = (DictionaryEntry) i.Current;
			}
			if (itod.ContainsKey(indirectReference))
			{			
				return itod[indirectReference];
			}
			throw new AccessControlException("Access denied", "Request for invalid indirect reference");
		}    
    }
}
