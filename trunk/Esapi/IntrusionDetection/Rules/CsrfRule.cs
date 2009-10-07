using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.IntrusionDetection.Rules
{
    /// <summary>
    /// Intrusion detection CSRF rule
    /// </summary>
    public class CsrfRule : IRule
    {
        #region IRule Members

        /// <summary>
        /// Process CSRF rule
        /// </summary>
        /// <param name="args"></param>
        public void Process(RuleArgs args)
        {
            if (args == null) {
                throw new ArgumentNullException("args");
            }

            IntrusionRuleArgs intrusionArgs = (IntrusionRuleArgs)args;

            switch (intrusionArgs.Stage) {
                case RequestStage.PreRequestHandlerExecute:
                    Esapi.HttpUtilities.VerifyCsrfToken();
                    break;
                case RequestStage.PostRequestHandlerExecute:
                    Esapi.HttpUtilities.AddCsrfToken();
                    break;
                default:
                    break;
            }            
        }

        #endregion
    }
}
