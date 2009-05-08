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

namespace Owasp.Esapi.Interfaces
{


    /// <summary> The IIntrusionDetector interface is intended to track security relevant events and identify attack behavior. The
    /// implementation can use as much state as necessary to detect attacks, but note that storing too much state will burden
    /// your system.
    /// [P]
    /// [img src="doc-files/IntrusionDetector.jpg" height="600">
    /// [P]
    /// [P]
    /// The interface is currently designed to accept exceptions as well as custom events. Implementations can use this
    /// stream of information to detect both normal and abnormal behavior.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    public interface IIntrusionDetector
    {

        /// <summary> Adds the exception to the IntrusionDetector.
        /// 
        /// </summary>
        /// <param name="exception">The exception to add.
        /// </param>        
        void AddException(Exception exception);

        /// <summary> Adds the event to the IntrusionDetector.
        /// 
        /// </summary>
        /// <param name="eventName">The event to add.
        /// </param>        
        void AddEvent(string eventName);
    }
}
