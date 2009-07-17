using System;

namespace Owasp.Esapi.Interfaces
{               
    /// <summary> The ILogger interface defines a set of methods that can be used to log
    /// security events. Implementors should use a well established logging library
    /// as it is quite difficult to create a high-performance logger.
    /// <img src="doc-files/Logger.jpg" height="600"/>
    /// 
    ///  The logging levels defined by this interface (in descending order) are:
    /// <ul>
    /// <li>fatal (highest value)</li>
    /// <li>error</li>
    /// <li>warning</li>
    /// <li>info</li>
    /// <li>debug</li>
    /// <li>all</li>
    /// </ul>
    /// 
    /// This Logger allows callers to determine which logging levels are enabled, and to submit events 
    /// at different severity levels.<br>
    /// <br>Implementors of this interface should:
    /// 
    /// <ol>
    /// <li>provide a mechanism for setting the logging level threshold that is currently enabled. This usually works by logging all 
    /// events at and above that severity level, and discarding all events below that level.
    /// This is usually done via configuration, but can also be made accessible programmatically.</li>
    /// <li>ensure that dangerous HTML characters are encoded before they are logged to defend against malicious injection into logs 
    /// that might be viewed in an HTML based log viewer.</li>
    /// <li>encode any CRLF characters included in log data in order to prevent log injection attacks.</li>
    /// <li>avoid logging the user's session ID. Rather, they should log something equivalent like a 
    /// generated logging session ID, or a hashed value of the session ID so they can track session specific 
    /// events without risking the exposure of a live session's ID.</li> 
    /// <li>record the following information with each event:</li>
    ///   <ol type="a">
    ///   <li>identity of the user that caused the event,</li>
    ///   <li>a description of the event (supplied by the caller),</li>
    ///   <li>whether the event succeeded or failed (indicated by the caller),</li>
    ///   <li>severity level of the event (indicated by the caller),</li>
    ///   <li>that this is a security relevant event (indicated by the caller),</li>
    ///   <li>hostname or IP where the event occurred (and ideally the user's source IP as well),</li>
    ///   <li>a time stamp</li>
    ///   </ol>
    /// </ol>
    ///  
    /// Custom logger implementations might also:
    /// <ol start="6">
    /// <li>filter out any sensitive data specific to the current application or organization, such as credit cards, 
    /// social security numbers, etc.</li>
    /// </ol>
    /// 
    /// In the default implementation, this interface is implemented by Logger. 
    /// Logger uses the log4net package as the basis for its logging 
    /// implementation. This default implementation implements requirements #1 thru #5 above.
    /// 
    /// Customization: It is expected that most organizations will implement their own custom Logger class in 
    /// order to integrate ESAPI logging with their logging infrastructure. The ESAPI Reference Implementation 
    /// is intended to provide a simple functional example of an implementation.
    /// 
    /// </summary>  
    public interface ILogger
    {            
        int Level { get; set;}

        /// <summary> Log a fatal event if 'fatal' level logging is enabled.</summary>
        /// <param name="type">The type of event.
        /// </param>
		/// <param name="message">The message to log.
		/// </param>
		void Fatal(int type, string message);

        /// <summary> 
        /// Log a fatal level security event if 'fatal' level logging is enabled 
        /// and also record the stack trace associated with the event.
        /// </summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        /// <param name="exception">The exception to log.
        /// </param>
        void Fatal(int type, string message, Exception exception);

        /// <summary>
        /// Allows the caller to determine if messages logged at this level
        /// will be discarded, to avoid performing expensive processing.
        /// </summary>
        /// <returns>true, if fatal level messages will be output to the log.</returns>
        bool IsFatalEnabled();

        /// <summary>Log an error level security event if 'error' level logging is enabled.</summary>
        /// <param name="type">The type of event
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        void Error(int type, string message);

        /// <summary>
        /// Log an error level security event if 'error' level logging is enabled 
        /// and also record the stack trace associated with the event.
        /// </summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>	
        void Error(int type, string message, Exception throwable);

        /// <summary>
        /// Allows the caller to determine if messages logged at this level
	    /// will be discarded, to avoid performing expensive processing.
        /// </summary>
        /// <returns>true, if error level messages will be output to the log.</returns>
        bool IsErrorEnabled();

        /// <summary> Log a warning level security event if 'warning' level logging is enabled.</summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        void Warning(int type, string message);

        /// <summary>
        /// Log a warning level security event if 'warning' level logging is enabled 
        /// and also record the stack trace associated with the event.
        /// </summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>			
        void Warning(int type, string message, Exception throwable);

        /// <summary>
        /// Allows the caller to determine if messages logged at this level
        /// will be discarded, to avoid performing expensive processing.
        /// </summary>
        /// <returns>true, if warning level messages will be output to the log.</returns>
        bool IsWarningEnabled();

        /// <summary> Log a warning level security event if 'info' level logging is enabled.</summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        void Info(int type, string message);

        /// <summary>
        /// Log a warning level security event if 'info' level logging is enabled 
        /// and also record the stack trace associated with the event.
        /// </summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>			
        void Info(int type, string message, Exception throwable);

        /// <summary>
        /// Allows the caller to determine if messages logged at this level
        /// will be discarded, to avoid performing expensive processing.
        /// </summary>
        /// <returns>true, if info level messages will be output to the log.</returns>
        bool IsInfoEnabled();

        /// <summary> Log a warning level security event if 'debug' level logging is enabled.</summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
		void  Debug(int type, string message);

        /// <summary>
        /// Log a warning level security event if 'debug' level logging is enabled 
        /// and also record the stack trace associated with the event.
        /// </summary>
        /// <param name="type">The type of event.
        /// </param>
        /// <param name="message">The message to log.
        /// </param>
        /// <param name="throwable">The exception to log.
        /// </param>	
		void Debug(int type, string message, Exception throwable);

        /// <summary>
        /// Allows the caller to determine if messages logged at this level
        /// will be discarded, to avoid performing expensive processing.
        /// </summary>
        /// <returns>true, if debug level messages will be output to the log.</returns>
        bool IsDebugEnabled();
    }
}
