using System;
using System.Web;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.IntrusionDetection
{
    /// <summary>
    /// Context selector arguments
    /// </summary>
    public class IntrusionConditionArgs : ConditionArgs
    {
        private Uri         _uri;
        private HttpContext _context;

        /// <summary>
        /// Initialize context selector args based on current HttpContext
        /// </summary>
        public IntrusionConditionArgs()
            : this(HttpContext.Current)
        {
        }

        /// <summary>
        /// Initialize context selector args from an HttpContext
        /// </summary>
        /// <param name="context">Http context</param>
        public IntrusionConditionArgs(HttpContext context)
        {
            if (context == null) {
                throw new ArgumentNullException("args");
            }
        
            _context = context;
            _uri = new Uri(context.Request.RawUrl);
        }

        /// <summary>
        /// HttpContext
        /// </summary>
        public HttpContext HttpContext
        {
            get { return _context; }
        }

        /// <summary>
        /// Request URI
        /// </summary>
        public Uri RequestUri
        {
            get { return _uri; }
        }
    };
}
