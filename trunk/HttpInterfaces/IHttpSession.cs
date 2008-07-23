using System;
using System.Collections;
using System.Collections.Specialized;
using System.Web;
using System.Web.SessionState;

namespace HttpInterfaces
{
	public interface IHttpSession : ICollection
	{       
	    
	    object this[string key] { get; set; }

		string SessionID { get; }

		int Timeout { get; set; }
	    
		bool IsNewSession { get; }

		SessionStateMode Mode { get; }

		bool IsCookieless { get; }

		HttpCookieMode CookieMode { get; }

		int LCID { get; set; }

		int CodePage { get; set;}

		IHttpSession Contents { get; }

		HttpStaticObjectsCollection StaticObjects { get; }

		NameObjectCollectionBase.KeysCollection Keys { get; }

		bool IsReadOnly { get; }

		void Abandon();

		void Add(string name, object value);

		void Remove(string name);

		void RemoveAt(int index);

		void Clear();

		void RemoveAll();
	}
}
