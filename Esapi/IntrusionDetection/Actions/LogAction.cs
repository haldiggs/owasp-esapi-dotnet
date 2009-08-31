using System;
using Owasp.Esapi.Interfaces;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi.IntrusionDetection.Actions
{
    /// <summary>
    /// Log threshold exceeded action
    /// </summary>
    [Action(BuiltinActions.Log)]
    public class LogAction : IAction
    {
        #region IAction Members

        /// <summary>
        /// Execute action
        /// </summary>
        /// <param name="args">Arguments</param>
        public void Execute(ActionArgs args)
        {
            IntrusionActionArgs iarg = (IntrusionActionArgs)args;

            string message = string.Format(EM.InstrusionDetector_ExceededQuota3, 
                                    iarg.Threshold.MaxOccurences, iarg.Threshold.MaxTimeSpan, iarg.Threshold.Event);
            Esapi.Logger.Fatal(LogEventTypes.SECURITY, message);
        }

        #endregion
    }
}
