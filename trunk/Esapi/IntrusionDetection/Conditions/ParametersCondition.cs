using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.IntrusionDetection.Conditions
{
    /// <summary>
    /// HTTP Request context selector
    /// </summary>
    public class ParametersCondition : ICondition
    {
        #region ICondition Members

        public bool Evaluate(ConditionArgs args)
        {
            if (args == null) {
                throw new ArgumentNullException("args");
            }

            return false;
        }

        #endregion
    }
}
