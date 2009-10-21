using System;
using System.Web;
using System.Threading;

namespace Owasp.Esapi.IntrusionDetection
{
    /// <summary>
    /// Intrusion detection HTTP module
    /// </summary>
    /// <remarks>Monitors application execution</remarks>
    public class IntrusionDetectionModule : IHttpModule
    {
        #region IHttpModule Members

        /// <summary>
        /// Dispose intrustion detection module
        /// </summary>
        public void Dispose()
        {            
        }

        /// <summary>
        /// Initialize instrusion detection module
        /// </summary>
        /// <param name="context"></param>
        public void Init(HttpApplication context)
        {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            context.Error += new EventHandler(OnError);
            context.PreRequestHandlerExecute += new EventHandler(OnPreRequestHandlerExecute);
            context.PostRequestHandlerExecute += new EventHandler(OnPostRequestHandlerExecute);
        }

        #endregion

        #region Event handlers

        /// <summary>
        /// Process post request handler execute rules
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void OnPostRequestHandlerExecute(object sender, EventArgs e)
        {            
        }

        /// <summary>
        /// Process pre request handler execute rules
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void OnPreRequestHandlerExecute(object sender, EventArgs e)
        {            
        }

        /// <summary>
        /// Intercept unhandled exceptions
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void OnError(object sender, EventArgs e)
        {
            if (HttpContext.Current == null) {
                return;
            }

            // Get current exception
            Exception exception = HttpContext.Current.Server.GetLastError();
            
            // Skip thread aborted exceptions
            if (!(exception is ThreadAbortException)) {
                Esapi.IntrusionDetector.AddException(exception);
            }
        }

        #endregion
    }
}
