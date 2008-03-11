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
using System.Web;
using System.Collections;
using System.Web.Profile;
using System.Security.Principal;

namespace Owasp.Esapi.Test.Http
{
    class MockHttpContext: IHttpContext
    {
        private Hashtable items = new Hashtable();
        private IHttpRequest request = new MockHttpRequest("", null);
        private MockHttpResponse response = new MockHttpResponse();
        private MockHttpSession session = new MockHttpSession();
        public MockHttpContext()
        {
        }

        public void AddError(Exception errorInfo)
        {
            throw new NotImplementedException();
        }
        public void ClearError()
        {
            throw new NotImplementedException();
        }
        public object GetSection(string sectionName)
        {
            throw new NotImplementedException();
        }
        public void RewritePath(string path)
        {
            throw new NotImplementedException();
        }
        public void RewritePath(string path, bool rebaseClientPath)
        {
            throw new NotImplementedException();
        }
        public void RewritePath(string filePath, string pathInfo, string queryString)
        {
            throw new NotImplementedException();
        }
        public void RewritePath(string filePath, string pathInfo, string queryString, bool setClientFilePath)
        {
            throw new NotImplementedException();
        }

        // Properties
        public Exception[] AllErrors
        {
            get { throw new NotImplementedException(); }
        }


        public IHttpApplicationState Application
        {
            get { throw new NotImplementedException(); }
        }
        
        public IHttpApplication ApplicationInstance
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

        public ICache Cache
        {
            get { throw new NotImplementedException(); }
        }
        public IHttpHandler CurrentHandler
        {
            get { throw new NotImplementedException(); }
        }
        public RequestNotification CurrentNotification
        {
            get { throw new NotImplementedException(); }
        }
        
        public Exception Error
        {
            get { throw new NotImplementedException(); }
        }
        public IHttpHandler Handler
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
        public bool IsCustomErrorEnabled 
        {
            get { throw new NotImplementedException(); }
        }
        public bool IsDebuggingEnabled
        {
            get { throw new NotImplementedException(); }
        }
        public bool IsPostNotification
        {
            get { throw new NotImplementedException(); }
        }
        public IDictionary Items 
        {
            get
            {
                return items;
            }
            set
            {
                items = (Hashtable) value;
            }
        }
        public IHttpHandler PreviousHandler
        {
            get { throw new NotImplementedException(); }
        }
        public ProfileBase Profile
        {
            get { throw new NotImplementedException(); }
        }
        public IHttpRequest Request
        {
            get { return request; }
            set { request = value; }
        }
        public IHttpResponse Response
        {
            get { return response; }
        }
        public IHttpServerUtility Server
        {
            get { throw new NotImplementedException(); }
        }
        public IHttpSession Session
        {
            get { return session; }
        }
        public bool SkipAuthorization
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
        public DateTime Timestamp
        {
            get { throw new NotImplementedException(); }
        }
        public ITraceContext Trace
        {
            get { throw new NotImplementedException(); }
        }
        public IPrincipal User
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
