/// <summary> OWASP Enterprise Security API .NET (Esapi.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (Esapi) project. For details, please see
/// http://www.owasp.org/Esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The Esapi is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using System.Collections;
using Owasp.Esapi.Interfaces;
using HttpInterfaces;
using System.Text;
using System.Diagnostics;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the ILogger interface. This implementation uses the log4NET logging package, and marks each
    /// log message with the currently logged in user and the word "SECURITY" for security related events.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> Febraury 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.ILogger">
    /// </seealso>
    public class Logger : ILogger
    {
        // FIXME: ENHANCE somehow make configurable so that successes and failures are logged according to a configuration.

        /// <summary>The Log4Net logger. </summary>
        private log4net.ILog logger = null;

        /// <summary>The application name. </summary>
        private string applicationName = null;

        /// <summary>The module name. </summary>
        private string moduleName = null;

        /// <summary> The constructor, which is hidden (private) and accessed through Esapi class.
        /// 
        /// </summary>
        /// <param name="applicationName">The application name.
        /// </param>
        /// <param name="moduleName">The module name.
        /// </param>
        /// <param name="logger">The log$net logger.
        /// </param>
        private Logger(string applicationName, string moduleName, log4net.ILog logger)
        {
            this.applicationName = applicationName;
            this.moduleName = moduleName;
            this.logger = logger;
            // FIXME: AAA this causes some weird classloading problem, since SecurityConfiguration logs.
            //log4net.Repository.Hierarchy.Logger logger = ((log4net.Repository.Hierarchy.Logger)log4net.LogManager.GetLogger("foo").Logger);         
            log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.All;
            //(SecurityConfiguration) Esapi.SecurityConfiguration()).LogLevel;            
        }

        public void LogHttpRequest()
        {
            LogHttpRequest(null);
        }
        
        /// <summary> Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or
        /// hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All
        /// the paramaters are presented as though they were in the URL even if they were in a form. Any parameters that
        /// match items in the parameterNamesToObfuscate are shown as eight asterisks.
        /// 
        /// </summary>
        /// <param name="parameterNamesToObfuscate">The sensitive parameters to obfuscate in the log entry.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogHttpRequest(IList)">
        /// </seealso>
        public virtual void LogHttpRequest(IList parameterNamesToObfuscate)
        {
            IHttpRequest request = ((Authenticator) Esapi.Authenticator()).Context.Request;
            StringBuilder parameters = new StringBuilder();
            IEnumerator i = request.Params.Keys.GetEnumerator();            
            while (i.MoveNext())
            {                
                string key = (string)i.Current;               
                // Note: Do we need to deal with multiple identical values here?
                string value = request.Params[key];
                parameters.Append(key + "=");
                if (parameterNamesToObfuscate!=null && parameterNamesToObfuscate.Contains(key))
                {
                    parameters.Append("********");
                }
                else
                {
                    parameters.Append(value);
                }                            
                if (i.MoveNext())
                    parameters.Append("&");
            }
            string msg = request.RequestType + " " + request.Url + (parameters.Length > 0 ? "?" + parameters : "");
            LogSuccess(ILogger_Fields.SECURITY, msg);
        }

        /// <summary> Gets the logger.
        /// 
        /// </summary>
        /// <param name="applicationName">The application name.
        /// </param>
        /// <param name="moduleName">The module name.
        /// </param>
        /// <returns> The logger.
        /// </returns>
        public static Logger GetLogger(string applicationName, string moduleName)
        {
            log4net.ILog logger = log4net.LogManager.GetLogger(applicationName + ":" + moduleName);
            return new Logger(applicationName, moduleName, logger);
        }


        /// <summary> Log trace messages.        
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogTrace(string, string, Exception)">
        /// </seealso>
        public virtual void LogTrace(string type, string message, Exception throwable)
        {
            string FullMessage = GetLogMessage(type, message, throwable);
            logger.Warn(FullMessage);
        }

        /// <summary> Log trace messages.        
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogTrace(string, string)">
        /// </seealso>
        public virtual void LogTrace(string type, string message)
        {
            string FullMessage = GetLogMessage(type, message, null);
            logger.Warn(FullMessage);
        }

        /// <summary> Log debug messages with exception information.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param> 
        /// <param name="throwable">The exception to log.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogDebug(string, string, Exception)">
        /// </seealso>
        public virtual void LogDebug(string type, string message, Exception throwable)
        {
            string FullMessage = GetLogMessage(type, message, throwable);
            logger.Debug(FullMessage);
        }

        /// <summary> Log debug messages.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogDebug(string, string)">
        /// </seealso>
        public virtual void LogDebug(string type, string message)
        {            
            string FullMessage = GetLogMessage(type, message, null);
            logger.Debug(FullMessage);
        }

        /// <summary> Log error messages with exception information.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogError(string, string, Exception)">
        /// </seealso>
        public virtual void LogError(string type, string message, Exception throwable)
        {
            string FullMessage = GetLogMessage(type, message, throwable);
            logger.Warn(FullMessage);
        }

        /// <summary> Log error message.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogError(string, string)">
        /// </seealso>
        public virtual void LogError(string type, string message)
        {
            string FullMessage = GetLogMessage(type, message, null);
            logger.Warn(FullMessage);            
        }

        /// <summary> Log success message.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogSuccess(string, string)">
        /// </seealso>
        public virtual void LogSuccess(string type, string message)
        {
            string FullMessage = GetLogMessage(type, message, null);
            logger.Info(FullMessage);
        }

        /// <summary> Log success message with exception information.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogSuccess(string, string, Exception)">
        /// </seealso>
        public virtual void LogSuccess(string type, string message, Exception throwable)
        {
            string FullMessage = GetLogMessage(type, message, throwable);
            logger.Info(FullMessage);
        }

        /// <summary> Log warning message with exception information.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogWarning(string, string, Exception)">
        /// </seealso>
        public virtual void LogWarning(string type, string message, Exception throwable)
        {
            string FullMessage = GetLogMessage(type, message, throwable);
            logger.Warn(FullMessage);            
        }

        /// <summary> Log warning message.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogWarning(string, string)">
        /// </seealso>
        public virtual void LogWarning(string type, string message)
        {
            string FullMessage = GetLogMessage(type, message, null);
            logger.Warn(FullMessage);
        }

        /// <summary> Log critical message with exception information.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogCritical(string, string, Exception)">
        /// </seealso>
        public virtual void LogCritical(string type, string message, Exception throwable)
        {
            string FullMessage = GetLogMessage(type, message, throwable);
            logger.Fatal(FullMessage);
        }

        /// <summary> Log critical message.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.ILogger.LogCritical(string, string)">
        /// </seealso>
        public virtual void LogCritical(string type, string message)
        {
            string FullMessage = GetLogMessage(type, message, null);
            logger.Fatal(FullMessage);
        }

        /// <summary> Log the message after optionally encoding any special characters that might inject into an HTML based log viewer.
        /// This method accepts an exception.
        /// 
        /// </summary>
        /// <param name="type">The log type.
        /// </param>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        private string GetLogMessage(string type, string message, Exception throwable)
        {
            User user = (User) Esapi.Authenticator().GetCurrentUser();

            string clean = message;
            if (((SecurityConfiguration)Esapi.SecurityConfiguration()).LogEncodingRequired)
            {
                clean = Esapi.Encoder().EncodeForHtml(message);
                if (!message.Equals(clean))
                {
                    clean += " (Encoded)";
                }
            }
            if (throwable != null)
            {                
                string fqn = throwable.GetType().FullName;
                int index = fqn.LastIndexOf('.');
                if (index > 0)
                    fqn = fqn.Substring(index + 1);
                StackTrace st = new StackTrace(throwable, true);
                
                // Note: Should we have exceptions with null stack traces?

                StackFrame[] frames = st.GetFrames();
                if (frames != null)
                {
                    StackFrame frame = frames[0];
                    clean += ("\n    " + fqn + " @ " + frame.GetType() + "." + frame.GetMethod() + "(" + frame.GetFileName() + ":" + frame.GetFileLineNumber() + ")");
                }
            }
            string msg = "";
            if (user != null)
            {
                msg = type + ": " + user.AccountName + "/" + user.GetLastHostAddress() + " -- " + clean;
            }

            return msg;                    
        }

        /// <summary> This special method doesn't include the current user's identity, and is only used during system initialization to
        /// prevent loops with the Authenticator.
        /// 
        /// </summary>
        /// <param name="message">The log message.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        public virtual void LogSpecial(string message, Exception throwable)
        {
            string msg = "SECURITY" + ": " + "Esapi" + "/" + "none" + " -- " + message;            
            logger.Warn(msg, throwable);

        }
    }
}
