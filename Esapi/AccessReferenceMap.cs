using System;
using System.Collections;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap"/>
    /// <remarks>
    /// This AccessReferenceMap implementation uses short random strings to
    /// create a layer of indirection. Other possible implementations would use
    /// simple integers as indirect references.
    /// </remarks>
    public class AccessReferenceMap:IAccessReferenceMap
    {    		
		internal Hashtable itod = new Hashtable();
		
		internal Hashtable dtoi = new Hashtable();
		
		internal IRandomizer random = Esapi.Randomizer;
		
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
			string indirect = random.GetRandomString(6, Encoder.CHAR_ALPHANUMERICS);
			itod[indirect] = direct;
			dtoi[direct] = indirect;
            return indirect;
		}

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.RemoveDirectReference(object)"/>	
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

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.Update(ICollection)"/>
		public void Update(ICollection directReferences)
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

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetIndirectReference(object)"/>
		public string GetIndirectReference(Object directReference)
		{			
			return (string) dtoi[directReference];
		}

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.GetDirectReference(string)"/>
		public object GetDirectReference(string indirectReference)
		{
		    if (itod.ContainsKey(indirectReference))
			{			
				return itod[indirectReference];
			}
			throw new AccessControlException("Access denied", "Request for invalid indirect reference");
		}    
    }
}
