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
using HttpInterfaces;
using System.Web.Caching;
using System.Collections;
using System.Web;
using System.Text;
using System.IO;
using System.Collections.Specialized;

namespace Owasp.Esapi.Test.Http
{
    class MockHttpResponse:IHttpResponse
    {
        private HttpCookieCollection cookies = new HttpCookieCollection();
        private NameValueCollection headers = new NameValueCollection();

        public void AddCacheDependency(params CacheDependency[] dependencies)
        {
            throw new NotImplementedException();
        }
        public void AddCacheItemDependencies(string[] cacheKeys)
        {
            throw new NotImplementedException();
        }
        public void AddCacheItemDependencies(ArrayList cacheKeys)
        {
            throw new NotImplementedException();
        }
        public void AddCacheItemDependency(string cacheKey)
        {
            throw new NotImplementedException();
        }
        public void AddFileDependencies(ArrayList filenames)
        {
            throw new NotImplementedException();
        }
        public void AddFileDependencies(string[] filenames)
        {
            throw new NotImplementedException();
        }
        public void AddFileDependency(string filename)
        {
            throw new NotImplementedException();
        }
        public void AddHeader(string name, string value)
        {
            throw new NotImplementedException();
        }
        public void AppendCookie(HttpCookie cookie)
        {
            throw new NotImplementedException();
        }
        public void AppendHeader(string name, string value)
        {
            headers.Add(name, value);
        }
        public void AppendToLog(string param)
        {
            throw new NotImplementedException();
        }
        public string ApplyAppPathModifier(string virtualPath)
        {
            throw new NotImplementedException();            
        }
        public void BinaryWrite(byte[] buffer)
        {
            throw new NotImplementedException();
        }
        public void Clear()
        {
            throw new NotImplementedException();
        }
        public void ClearContent()
        {
            throw new NotImplementedException();
        }
        public void ClearHeaders()
        {
            throw new NotImplementedException();
        }
        public void Close()
        {
            throw new NotImplementedException();
        }
        public void DisableKernelCache()
        {
            throw new NotImplementedException();
        }
        public void End()
        {
            throw new NotImplementedException();
        }
        public void Flush()
        {
            throw new NotImplementedException();
        }
        public void Pics(string value)
        {
            throw new NotImplementedException();
        }
        public void Redirect(string url)
        {
            return;
        }
        public void Redirect(string url, bool endResponse)
        {
            throw new NotImplementedException();
        }
        public void SetCookie(HttpCookie cookie)
        {
            throw new NotImplementedException();
        }
        public void TransmitFile(string filename)
        {
            throw new NotImplementedException();
        }
        public void TransmitFile(string filename, long offset, long length)
        {
            throw new NotImplementedException();
        }
        public void Write(char ch)
        {
            throw new NotImplementedException();
        }
        public void Write(object obj)
        {
            throw new NotImplementedException();
        }
        public void Write(string s)
        {
            throw new NotImplementedException();
        }
        public void Write(char[] buffer, int index, int count)
        {
            throw new NotImplementedException();
        }
        public void WriteFile(string filename)
        {
            throw new NotImplementedException();
        }
        public void WriteFile(string filename, bool readIntoMemory)
        {
            throw new NotImplementedException();
        }
        public void WriteFile(IntPtr fileHandle, long offset, long size)
        {
            throw new NotImplementedException();
        }
        public void WriteFile(string filename, long offset, long size)
        {
            throw new NotImplementedException();
        }
        public void WriteSubstitution(HttpResponseSubstitutionCallback callback)
        {
            throw new NotImplementedException();
        }
        // Properties
        public bool Buffer
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
        public bool BufferOutput
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
        public IHttpCachePolicy Cache
        {
            get { throw new NotImplementedException(); }
        }
        public string CacheControl
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
        public string Charset
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
        public Encoding ContentEncoding
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
        public string ContentType
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
        public HttpCookieCollection Cookies
        {
            get { return cookies; }
        }
        public int Expires
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
        public DateTime ExpiresAbsolute
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
        public Stream Filter
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
        public Encoding HeaderEncoding
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
        public NameValueCollection Headers
        {
            get { return headers;  }
        }
        public bool IsClientConnected
        {
            get { throw new NotImplementedException(); }
        }
        public bool IsRequestBeingRedirected
        {
            get { throw new NotImplementedException(); }
        }
        public TextWriter Output
        {
            get { throw new NotImplementedException(); }
        }
        public Stream OutputStream
        {
            get { throw new NotImplementedException(); }
        }
        public string RedirectLocation
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
        public string Status
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
        public int StatusCode
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
        public string StatusDescription
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
        public int SubStatusCode
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
        public bool SuppressContent
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
    }
}
