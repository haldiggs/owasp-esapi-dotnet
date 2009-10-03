using System.Web;
using System;

namespace Owasp.Esapi.IntrusionDetection
{
    /// <summary>
    /// Context selector arguments
    /// </summary>
    public class ContextConditionArgs
    {
        private Uri         _uri;
        private HttpContext _context;

        /// <summary>
        /// Initialize context selector args based on current HttpContext
        /// </summary>
        public ContextConditionArgs()
            : this(HttpContext.Current)
        {
        }

        /// <summary>
        /// Initialize context selector args from an HttpContext
        /// </summary>
        /// <param name="context">Http context</param>
        public ContextConditionArgs(HttpContext context)
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

    /// <summary>
    /// Context selector interface
    /// </summary>
    public interface IContextCondition
    {
        /// <summary>
        /// Matches current context
        /// </summary>
        /// <param name="args">Match arguments</param>
        /// <returns>True if match, false otherwise</returns>
        bool Evaluate(ContextConditionArgs args);
    }
}
