using System;
using System.Diagnostics;
using System.Security.Principal;
using log4net;
using Owasp.Esapi.Codecs;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <summary>
    ///  These are fields for the logger class.
    /// </summary>
    public class LogLevels
    {
        /// <summary>
        /// Logging is disabled.
        /// </summary>
        public static readonly int OFF = Int32.MaxValue;
        
        /// <summary>
        /// Only fatal log messages are recorded.
        /// </summary>
        public static readonly int FATAL = 1000;
        
        /// <summary>
        /// Only error-level log messages are recorded.
        /// </summary>
        public static readonly int ERROR = 800;
        
        /// <summary>
        /// Only warning-level log messages are recorded.
        /// </summary>
        public static readonly int WARN = 600;
        
        /// <summary>
        /// Only informational log messages are recorded.
        /// </summary>
        public static readonly int INFO = 400;
        
        /// <summary>
        ///  Only debug log messages are recoreded.
        /// </summary>
        public static readonly int DEBUG = 200;
        
        /// <summary>
        /// All log messages are recorded.
        /// </summary>
        public static readonly int ALL = Int32.MinValue;
        
        /// <summary>
        /// This method parses the string indiciating log level and returns the appropriate integer.
        /// </summary>
        /// <param name="level">The string indicating the log level.</param>
        /// <returns>The integer representing the log level.</returns>
        public static int ParseLogLevel(string level)
        {
            if (!string.IsNullOrEmpty(level)) {
                if (0 == string.Compare(level, "FATAL", StringComparison.InvariantCultureIgnoreCase))
                    return LogLevels.FATAL;
                if (0 == string.Compare(level, "ERROR", StringComparison.InvariantCultureIgnoreCase))
                    return LogLevels.ERROR;
                if (0 == string.Compare(level, "WARNING", StringComparison.InvariantCultureIgnoreCase))
                    return LogLevels.WARN;
                if (0 == string.Compare(level, "INFO", StringComparison.InvariantCultureIgnoreCase))
                    return LogLevels.INFO;
                if (0 == string.Compare(level, "DEBUG", StringComparison.InvariantCultureIgnoreCase))
                    return LogLevels.DEBUG;
                if (0 == string.Compare(level, "OFF", StringComparison.InvariantCultureIgnoreCase))
                    return LogLevels.OFF;
            }
            return LogLevels.ALL;
        }
    }
    
    /// <summary>
    /// This class contains the keys for the different event types that can be passed to the logger.
    /// </summary>
    public class LogEventTypes
    {
        /// <summary>
        /// Used for security events.
        /// </summary>
        public static readonly int SECURITY = 0;
        
        /// <summary>
        /// Used for usability events.
        /// </summary>
        public static readonly int USABILITY = 1;
        
        /// <summary>
        /// Used for performance events.
        /// </summary>
        public static readonly int PERFORMANCE = 2;
        
        /// <summary>
        /// Used for functionality events.
        /// </summary>
        public static readonly int FUNCTIONALITY = 3;
        
        internal static string GetType(int type)
        {
            switch (type)
            {
                case 0:
                    return "SECURITY";    
                case 1:
                    return "USABILITY";
                case 2:
                    return "PERFORMANCE";
                case 3:
                    return "FUNCTIONALITY";
            }
            return "UNDEFINED";
        }
    }

    /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger"/>
    /// <summary>
    /// Reference implementation of the <see cref="Owasp.Esapi.Interfaces.ILogger" /> interface. This implementation uses the Log4Net logging package, 
    /// and marks each log message with the currently logged in user and the word "SECURITY" for security related events.
    /// </summary>
    public class Logger : ILogger
    {
        /// <summary>The Log4Net logger.</summary>
        private ILog logger;

        /// <summary>The application name.</summary>
        private string applicationName;

        /// <summary>The module name.</summary>
        private string moduleName;

        static Logger()
        {
            log4net.Config.XmlConfigurator.Configure();
        }

        /// <summary>
        /// The constructor, which is hidden (private) and accessed through Esapi class.       
        /// </summary>
        public Logger(string className)
        {
            this.logger = log4net.LogManager.GetLogger(className);
            Level = Esapi.SecurityConfiguration.LogLevel;
            if (Level == LogLevels.FATAL) {
                log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.Fatal;
            }
            else if (Level == LogLevels.ERROR)
            {
                log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.Error;
            }
            else if (Level == LogLevels.WARN)
            {
                log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.Warn;
            }
            else if (Level == LogLevels.INFO)
            {
                log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.Info;
            }
            else if (Level == LogLevels.DEBUG)
            {
                log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.Debug;
            }
            else if (Level == LogLevels.OFF)
            {
                log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.Off;
            }
            else
            {
                log4net.LogManager.GetRepository().Threshold = log4net.Core.Level.All;
            }

        }
        
        /// <summary>
        /// The constructor, which is hidden (private) and accessed through Esapi class.       
        /// </summary>
        /// <param name="applicationName">The application name.
        /// </param>
        /// <param name="moduleName">The module name.
        /// </param>
        private Logger(string applicationName, string moduleName)
        {
            this.applicationName = applicationName;
            this.moduleName = moduleName;            
        }
        
        /// <summary> Log the message after optionally encoding any special characters that might inject into an HTML 
        /// based log viewer. This method accepts an exception.
        /// </summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>
        private string GetLogMessage(int type, string message, Exception throwable)
        {
            IPrincipal currentUser = Esapi.SecurityConfiguration.CurrentUser;
                        
            // Ensure no CRLF injection into logs for forging records
            string clean = !string.IsNullOrEmpty(message) ?
                                message.Replace('\n', '_').Replace('\r', '_') :
                                message;
            
            // HTML encode log message if it will be viewed in a web browser
            if (Esapi.SecurityConfiguration.LogEncodingRequired)
            {
                clean = Esapi.Encoder.Encode(BuiltinCodecs.Html, message);
                if (!message.Equals(clean))
                {
                    clean += " (Encoded)";
                }
            }
            
            // Add a printable stack trace
            if (throwable != null)
            {                
                string fqn = throwable.GetType().FullName;
                int index = fqn.LastIndexOf('.');
                if (index > 0)
                    fqn = fqn.Substring(index + 1);
                StackTrace st = new StackTrace(throwable, true);
                
                StackFrame[] frames = st.GetFrames();
                if (frames != null)
                {
                    StackFrame frame = frames[0];
                    clean += ("\n    " + throwable.Message + " - " + fqn + " @ " + "(" + frame.GetFileName() + ":" + frame.GetFileLineNumber() + ")");
                }
            }
            
            string msg;

            if (currentUser != null && currentUser.Identity != null) {
                msg = LogEventTypes.GetType(type) + ": " + currentUser.Identity.Name + ": " + clean;
            }
            else {
                msg = LogEventTypes.GetType(type) + ": "  + clean;
            }
        
            return msg;                    
        }

        #region ILogger Members

        private int level;

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Level"/>
        public int Level
        {
            get
            {
                return level;                
            }
            set
            {
                level = value;
            }
        }


        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Fatal(int, string)"/>
        public void Fatal(int type, string message)
        {

            if (logger.IsFatalEnabled)
            {
                logger.Fatal(GetLogMessage(type, message, null));
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Fatal(int, string, Exception)"/>
        public void Fatal(int type, string message, Exception exception)
        {
            if (logger.IsFatalEnabled)
            {
                logger.Fatal(GetLogMessage(type, message, exception));
            }
       }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.IsFatalEnabled()"/>
        public bool IsFatalEnabled()
        {
            return (logger.IsFatalEnabled);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Error(int, string)"/>
        public void Error(int type, string message)
        {
            if (logger.IsErrorEnabled)
            {
                logger.Error(GetLogMessage(type, message, null));
            }
        }
        
        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Error(int, string, Exception)"/>
        public void Error(int type, string message, Exception throwable)
        {
            if (logger.IsErrorEnabled)
            {
                logger.Error(GetLogMessage(type, message, throwable));
            }          
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.IsErrorEnabled()"/>
        public bool IsErrorEnabled()
        {
            return (logger.IsErrorEnabled);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Warning(int, string)"/>
        public void Warning(int type, string message)
        {
            if (logger.IsWarnEnabled)
            {
                logger.Warn(GetLogMessage(type, message, null));
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Warning(int, string, Exception)"/>
        public void Warning(int type, string message, Exception throwable)
        {
            if (logger.IsWarnEnabled)
            {
                logger.Warn(GetLogMessage(type, message, throwable));
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.IsWarningEnabled()"/>
        public bool IsWarningEnabled()
        {
            return (logger.IsWarnEnabled);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Info(int, string)"/>
        public void Info(int type, string message)
        {
            if (logger.IsInfoEnabled)
            {
                logger.Info(GetLogMessage(type, message, null));
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Info(int, string, Exception)"/>
        public void Info(int type, string message, Exception throwable)
        {
            if (logger.IsInfoEnabled)
            {
                logger.Info(GetLogMessage(type, message, throwable));
            }
            
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.IsInfoEnabled()"/>
        public bool IsInfoEnabled()
        {
            return logger.IsInfoEnabled;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Debug(int, string)"/>
        public void Debug(int type, string message)
        {
            if (logger.IsDebugEnabled)
            {
                logger.Debug(GetLogMessage(type, message, null));
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.Debug(int, string, Exception)"/>
        public void Debug(int type, string message, Exception throwable)
        {
            if (logger.IsDebugEnabled)
            {
                logger.Debug(GetLogMessage(type, message, throwable));
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ILogger.IsDebugEnabled()"/>
        public bool IsDebugEnabled()
        {
            return logger.IsDebugEnabled;
        }


        #endregion
    }
}
