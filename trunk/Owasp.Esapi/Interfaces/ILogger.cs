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
using System.Collections;
using HttpInterfaces;

namespace Owasp.Esapi.Interfaces
{

    // Have to add this struct because interfaces in .NET cannot have member variables.
    /// <summary>
    ///  These are fields for the logger class
    /// </summary>
    public struct ILogger_Fields
    {
        /// <summary>The SECURITY. </summary>
        public readonly static string SECURITY = "SECURITY";
        /// <summary>The USABILITY. </summary>
        public readonly static string USABILITY = "USABILITY";
        /// <summary>The PERFORMANCE. </summary>
        public readonly static string PERFORMANCE = "PERFORMANCE";
    }




    /// <summary> The ILogger interface defines a set of methods that can be used to log
    /// security events. Implementors should use a well established logging library
    /// as it is quite difficult to create a high-performance logger.
    /// [P]
    /// [img src="doc-files/Logger.jpg" height="600"]
    /// [P]
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>   
    public interface ILogger
    {			
		// FIXME: ENHANCE Is this type approach right? Should it be configurable somehow?
		
		/// <summary> Format the Source IP address, URL, URL parameters, and all form
		/// parameters into a string for the log file. The list of parameters to
		/// obfuscate should be specified in order to prevent sensitive informatiton
		/// from being logged. If a null list is provided, then all parameters will
		/// be logged.
		/// </summary>
		/// <param name="type">The log type.
		/// </param>
		/// <param name="request">The request object to validate.
		/// </param>
		/// <param name="parameterNamesToObfuscate">The sensitive parameters to obfuscate in the log entry.
		/// </param>
		void  LogHttpRequest(string type, IHttpRequest request, IList parameterNamesToObfuscate);
		
		
		/// <summary> Log critical messages.
		/// 
		/// </summary>
		/// <param name="type">The log type.
		/// </param>
		/// <param name="message">The log message.
		/// </param>
		void  LogCritical(string type, string message);
		
		/// <summary> Log critical messages with exception information.
		/// 
		/// </summary>
		/// <param name="type">The log type.
		/// </param>
		/// <param name="message">The log message.
		/// </param>
		/// <param name="throwable">The exception.
		/// </param>		
		void  LogCritical(string type, string message, System.Exception throwable);
		
		/// <summary> Log debug messages.
		/// </summary>
		/// <param name="type">The log type.
		/// </param>
		/// <param name="message">The log message.
		/// </param>
		void  LogDebug(string type, string message);
		
		/// <summary> Log debug messages with exception information.
		/// 
		/// </summary>
		/// <param name="type">The log type.
		/// </param>
		/// <param name="message">The log message.
		/// </param>
		/// <param name="throwable">The exception to log.
		/// </param>		
		void  LogDebug(string type, string message, System.Exception throwable);
		
		/// <summary> Log error message.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
		void  LogError(string type, string message);
		
		/// <summary> Log error message with exception information.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>	
		void  LogError(string type, string message, System.Exception throwable);
		
		/// <summary> Log success message.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
		void  LogSuccess(string type, string message);
		
		/// <summary> Log success message with exception information.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>			
		void  LogSuccess(string type, string message, System.Exception throwable);
		
		/// <summary> Log trace messages.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
		void  LogTrace(string type, string message);
		
		/// <summary> Log trace message with exception information.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>			
		void  LogTrace(string type, string message, System.Exception throwable);
		
		/// <summary> Log warning message.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
		void  LogWarning(string type, string message);
		
		/// <summary> Log warning message with exception information.
		/// 
		/// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>			
		void  LogWarning(string type, string message, System.Exception throwable);
    }
}
