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
using System.Collections;
using System.Text.RegularExpressions;

namespace Owasp.Esapi.Test.Http
{
    class MockHttpFileCollection:IHttpFileCollection
    {
        Hashtable files = new Hashtable();
        public string[] AllKeys
        {
            get { return (string []) new ArrayList(files.Keys).ToArray(typeof(String)); }
        }

        public IHttpPostedFile Get(string name)
        {
            throw new NotImplementedException();
        }

        public IHttpPostedFile Get(int index)
        {
            throw new NotImplementedException();
        }

        public string GetKey(int index)
        {
            throw new NotImplementedException();
        }

        public IHttpPostedFile this[int index]
        {
            get { throw new NotImplementedException(); }
        }

        public IHttpPostedFile this[string name]
        {
            get { return (IHttpPostedFile) files[name]; }
        }

        public void AddFile(MockHttpPostedFile file)
        {
            files.Add(file.FileName,file);
        }

    }
}
