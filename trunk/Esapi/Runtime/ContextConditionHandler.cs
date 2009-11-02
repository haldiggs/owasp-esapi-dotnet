using System;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Context bound condition
    /// </summary>
    /// <remarks>Bounds a condition result to a context</remarks>
    public class ContextBoundCondition
    {
        private ICondition _condition;
        private bool _result;

        /// <summary>
        /// Initialize condition
        /// </summary>
        /// <param name="condition"></param>
        public ContextBoundCondition(ICondition condition)
            : this(condition, true)
        {
        }
        /// <summary>
        /// Initialize condition
        /// </summary>
        /// <param name="condition"></param>
        /// <param name="result"></param>
        public ContextBoundCondition(ICondition condition, bool result)
        {
            if (condition == null) {
                throw new ArgumentNullException("condition");
            }

            _condition = condition;
            _result = result;
        }

        /// <summary>
        /// Condition
        /// </summary>
        public ICondition Condition
        {
            get { return _condition; }
        }
        /// <summary>
        /// Condition evaluation result
        /// </summary>
        public bool Result
        {
            get { return _result; }
        }        
    }    
}
