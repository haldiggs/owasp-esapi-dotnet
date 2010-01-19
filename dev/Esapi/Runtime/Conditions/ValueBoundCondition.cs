using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Owasp.Esapi.Runtime.Conditions
{
    /// <summary>
    /// Value bound condition
    /// </summary>
    public class ValueBoundCondition : ICondition
    {
        private bool _value;

        /// <summary>
        /// Initialize condition
        /// </summary>
        /// <param name="value">Bounded value</param>
        public ValueBoundCondition(bool value)
        {
            _value = value;
        }
        /// <summary>
        /// Bound value
        /// </summary>
        public bool Value
        {
            get { return _value; }
            set { _value = value; }
        }

        #region ICondition Members
        /// <summary>
        /// Eval
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public bool Evaluate(ConditionArgs args)
        {
            return _value;
        }

        #endregion
    }
}
