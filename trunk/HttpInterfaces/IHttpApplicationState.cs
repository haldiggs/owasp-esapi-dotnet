using System;
using System.Web;

namespace HttpInterfaces
{
	public interface IHttpApplicationState
	{
		void Add(string name, object value);
		void Clear();
		object Get(int index);
		object Get(string name);
		string GetKey(int index);
		void Lock();
		void Remove(string name);
		void RemoveAll();
		void RemoveAt(int index);
		void Set(string name, object value);
		void UnLock();

		// Properties
		int Count { get; }
		string[] AllKeys { get; }
		IHttpApplicationState Contents { get; }
		object this[int index] { get; }
		object this[string name] { get; set; }
		HttpStaticObjectsCollection StaticObjects { get; }
	}
}
