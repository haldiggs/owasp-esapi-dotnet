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
using System.Collections;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi
{
    /// <summary> Reference implemenation of the IAccessReferenceMap interface. This implementation generates random 6 character alphanumeric strings for
    /// indirect references. It is possible to use simple integers as indirect references, but the random string approach provides a certain level of
    /// protection from CSRF attacks, because an attacker would have difficulty guessing the indirect reference. 
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IAccessReferenceMap">
    /// </seealso>
    public class AccessReferenceMap: IAccessReferenceMap
    {
		private void  InitBlock()
		{
			random = Esapi.Randomizer();
		}
		
		/// <summary>The itod. </summary>		
		internal Hashtable itod = new Hashtable();
		
		/// <summary>The dtoi. </summary>
		
		internal Hashtable dtoi = new Hashtable();
		
		/// <summary>The random. </summary>		
		internal IRandomizer random;
		
		/// <summary> This AccessReferenceMap implementation uses short random strings to
		/// create a layer of indirection. Other possible implementations would use
		/// simple integers as indirect references.
		/// </summary>
		public AccessReferenceMap()
		{
			InitBlock();
			// call update to set up the references
		}
		
		/// <summary> Instantiates a new access reference map.
		/// 
		/// </summary>
		/// <param name="directReferences">The direct references.
		/// </param>
		public AccessReferenceMap(IList directReferences)
		{
			InitBlock();
			Update(directReferences);
		}

        /// <summary> Get an enumerator through the direct object references.
        /// 
        /// </summary>
        /// <returns> The enumerator through the direct object referneces.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessReferenceMap.Enumerator()">
        /// </seealso>
		public IEnumerator Enumerator()
		{
			SortedList sorted = new SortedList(dtoi);
			return sorted.Keys.GetEnumerator();
		}
		
		/// <summary> Adds a direct reference and a new random indirect reference, overwriting any existing values.</summary>
		/// <param name="direct">
        ///     The direct reference.
		/// </param>
		public void AddDirectReference(string direct)
		{
			string indirect = random.GetRandomString(6, Encoder.CHAR_ALPHANUMERICS);
			itod[indirect] = direct;
			dtoi[direct] = indirect;
		}
		
		
		// FIXME: add addDirectRef and removeDirectRef to IAccessReferenceMap
		// FIXME: add test code for add/remove direct ref
		
		/// <summary> Remove a direct reference and the corresponding indirect reference.</summary>
		/// <param name="direct">The direct reference.
		/// </param>
		public void RemoveDirectReference(string direct)
		{			
			string indirect = (string) dtoi[direct];
			if (indirect != null)
			{
				itod.Remove(indirect);
				dtoi.Remove(direct);
			}
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
		public void Update(IList directReferences)
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
				// csollide with any existing indirect references
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
