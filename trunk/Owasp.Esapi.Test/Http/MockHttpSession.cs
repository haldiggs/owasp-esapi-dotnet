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
using HttpInterfaces;
using System.Web.SessionState;
using System.Collections;
using System.Web;

namespace Owasp.Esapi.Test.Http
{
    class MockHttpSession:IHttpSession
    {

        Hashtable contents = new Hashtable();
        String sessionId = Guid.NewGuid().ToString();
        int timeout = 20;

        public void Abandon()
        {
            contents = new Hashtable();

            // TODO: This is a hack, since ASP.NET sessions don't actually do this.
            sessionId = Guid.NewGuid().ToString();
        }

        public void Add(string name, object value)
        {
            contents.Add(name, value);
        }

        public void Clear()
        {
            throw new NotImplementedException();
        }

        public int CodePage
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public IHttpSession Contents
        {
            get { throw new NotImplementedException(); }
        }

        public System.Web.HttpCookieMode CookieMode
        {
            get { throw new NotImplementedException(); }
        }

        public bool IsCookieless
        {
            get { throw new NotImplementedException(); }
        }

        public bool IsNewSession
        {
            get { throw new NotImplementedException(); }
        }

        public bool IsReadOnly
        {
            get { throw new NotImplementedException(); }
        }

        public System.Collections.Specialized.NameObjectCollectionBase.KeysCollection Keys
        {
            get { throw new NotImplementedException(); }
        }

        public int LCID
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public SessionStateMode Mode
        {
            get { throw new NotImplementedException(); }
        }

        public void Remove(string name)
        {
            throw new NotImplementedException();
        }

        public void RemoveAll()
        {
            throw new NotImplementedException();
        }

        public void RemoveAt(int index)
        {
            throw new NotImplementedException();
        }

        public string SessionID
        {            
            get { return sessionId; }
        }

        public HttpStaticObjectsCollection StaticObjects
        {
            get { throw new NotImplementedException(); }
        }

        public int Timeout
        {
            get
            {
                return timeout;
            }
            set
            {
                timeout = value;
            }
        }

        public object this[string key]
        {
            get
            {
                return contents[key];
            }
            set
            {
                contents[key] = value;
            }
        }

        #region ICollection Members

        public void CopyTo(Array array, int index)
        {
            throw new NotImplementedException();
        }

        public int Count
        {
            get { throw new NotImplementedException(); }
        }

        public bool IsSynchronized
        {
            get { throw new NotImplementedException(); }
        }

        public object SyncRoot
        {
            get { throw new NotImplementedException(); }
        }

        #endregion

        #region IEnumerable Members

        public IEnumerator GetEnumerator()
        {
            return contents.Keys.GetEnumerator();
        }

        #endregion
    }
}
