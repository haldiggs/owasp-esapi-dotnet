using System;
using System.Web;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.IntrusionDetection
{
    /// <summary>
    /// Request processing stage
    /// </summary>
    public enum RequestStage
    {
        /// <summary>
        /// Before request handler is executed
        /// </summary>
        PreRequestHandlerExecute,
        /// <summary>
        /// After request handler is executed
        /// </summary>
        PostRequestHandlerExecute
    }

    /// <summary>
    /// Input rule arguments
    /// </summary>
    public class IntrusionRuleArgs  : RuleArgs
    {
        private RequestStage _stage;

        /// <summary>
        /// Initialize rule arguments
        /// </summary>
        /// <param name="stage">Request stage</param>
        public IntrusionRuleArgs(RequestStage stage)
        {
            _stage = stage;
        }

        /// <summary>
        /// Request stage
        /// </summary>
        public RequestStage Stage
        {
            get { return _stage; }
        }
    }
}
