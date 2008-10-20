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
using System.Web;
using HttpInterfaces;
using System.IO;


namespace Owasp.Esapi.Test.Http
{
    class MockHttpPostedFile: IHttpPostedFile
    {
        private string fullName;
        public MockHttpPostedFile(string fullName)
        {
            this.fullName = fullName;
        }

        public int ContentLength
        {
            get { throw new NotImplementedException(); }
        }
        public string ContentType
        {
            get { throw new NotImplementedException(); }
        }
        public string FileName
        {
            get { return fullName; }
        }
        public Stream InputStream
        {
            get { throw new NotImplementedException(); }
        }

        public void SaveAs(string fileName)
        {
            File.Create(fileName);
        }
    }
}
