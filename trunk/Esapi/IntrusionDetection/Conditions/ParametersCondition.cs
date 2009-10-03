using System;

namespace Owasp.Esapi.IntrusionDetection.Conditions
{
    /// <summary>
    /// HTTP Request context selector
    /// </summary>
    public class ParametersCondition : IContextCondition
    {
        #region IContextSelector Members

        public bool Evaluate(ContextConditionArgs args)
        {
            if (args == null) {
                throw new ArgumentNullException("args");
            }

            return false;
        }

        #endregion
    }
}
