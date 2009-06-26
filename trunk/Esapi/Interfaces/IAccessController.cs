/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/Category:ESAPI.
/// 
/// Copyright (c) 2009 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the BSD. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen
/// </author>
/// <created>  2008 </created>

using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// </summary>
    /// <author>  Alex Smolen (me@alexsmolen.com)
    /// </author>
    public interface IAccessController
    {
        bool IsAuthorized(object action, object resource);
        bool IsAuthorized(object subject, object action, object resource);
        void AddRule(object subject, object action, object resource);
        void RemoveRule(object subject, object action, object resource);
    }
}
