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
using System.Web;
using HttpInterfaces;
using System.Text;
using System.Collections.Specialized;
using System.IO;


namespace Owasp.Esapi.Test.Http
{
    class MockHttpRequest: IHttpRequest
    {
        private string userHostName = "";
        private string userHostAddress = "";
        private NameValueCollection parameters = new NameValueCollection();
        private Uri url = new Uri("https://localhost/");
        private HttpCookieCollection cookies = new HttpCookieCollection();
        private NameValueCollection headers = new NameValueCollection();
        private NameValueCollection form = new NameValueCollection();
        private NameValueCollection queryString = new NameValueCollection();
        private IHttpFileCollection fileCollection;
        public MockHttpRequest(string path, byte[] data)
        {            
        }

        public byte[] BinaryRead(int count)
        {
            throw new NotImplementedException();
        }
        public int[] MapImageCoordinates(string imageFieldName)
        {
            throw new NotImplementedException();
        }
        public string MapPath(string virtualPath)
        {
            throw new NotImplementedException();
        }
        public string MapPath(string virtualPath, string baseVirtualDir, bool allowCrossAppMapping)
        {
            throw new NotImplementedException();
        }
        public void SaveAs(string filename, bool includeHeaders)
        {
            throw new NotImplementedException();
        }
        public void ValidateInput()
        {
            throw new NotImplementedException();
        }

        public string[] AcceptTypes
        {
            get { throw new NotImplementedException(); }
        }
        public string AnonymousID
        {
            get { throw new NotImplementedException(); }
        }
        public string ApplicationPath
        {
            get { return null;  }
        }
        public string AppRelativeCurrentExecutionFilePath
        {
            get { throw new NotImplementedException(); }
        }
        public HttpBrowserCapabilities Browser
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
        public IHttpClientCertificate ClientCertificate
        {
            get { throw new NotImplementedException(); }
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
        public int ContentLength
        {
            get { throw new NotImplementedException(); }
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
        public string CurrentExecutionFilePath
        {
            get { throw new NotImplementedException(); }
        }
        public string FilePath
        {
            get { throw new NotImplementedException(); }
        }
        public IHttpFileCollection Files
        {
            get 
            {                
                return fileCollection;            
            }
            set
            {
                fileCollection = value;
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
        public NameValueCollection Form
        {
            get { return form; }
        }
        public NameValueCollection Headers
        {
            get { return headers; }
        }
        public string HttpMethod
        {
            get { throw new NotImplementedException(); }
        }
        public Stream InputStream
        {
            get { throw new NotImplementedException(); }
        }
        public bool IsAuthenticated
        {
            get { throw new NotImplementedException(); }
        }
        public bool IsLocal
        {
            get { throw new NotImplementedException(); }
        }
        public bool IsSecureConnection
        {
            get { throw new NotImplementedException(); }
        }
        public string this[string key]
        {
            get { return parameters[key]; }
        }
        public NameValueCollection Params
        {
            get { return parameters; }
        }
        public string Path
        {
            get { throw new NotImplementedException(); }
        }
        public string PathInfo
        {
            get { throw new NotImplementedException(); }
        }
        public string PhysicalApplicationPath
        {
            get { throw new NotImplementedException(); }
        }
        public string PhysicalPath
        {
            get { throw new NotImplementedException(); }
        }
        public NameValueCollection QueryString
        {
            get { return queryString; }
        }
        public string RawUrl
        {
            get { throw new NotImplementedException(); }
        }
        public string RequestType
        {
            get
            {
                return "POST";
            }
            set
            {
                throw new NotImplementedException();
            }
        }
        public NameValueCollection ServerVariables
        {
            get { throw new NotImplementedException(); }
        }
        public int TotalBytes
        {
            get { throw new NotImplementedException(); }
        }
        public Uri Url
        {
            get { return url; }
        }
        public Uri UrlReferrer
        {
            get { throw new NotImplementedException(); }
        }
        public string UserAgent
        {
            get { throw new NotImplementedException(); }
        }
        public string UserHostAddress
        {
            get { return userHostAddress; }
        }
        public string UserHostName
        {
            get { return userHostName; }
        }
        public string[] UserLanguages
        {
            get { throw new NotImplementedException(); }
        }
    }
}
