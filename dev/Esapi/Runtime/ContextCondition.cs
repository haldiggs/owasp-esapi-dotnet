using System;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Runtime context condition
    /// </summary>
    internal class ContextCondition : IContextCondition
    {
        private bool _result;
        private ICondition _condition;

        public ContextCondition(ICondition condition)
            : this(condition, true)
        {
        }

        /// <summary>
        /// Initialize condition
        /// </summary>
        /// <param name="condition"></param>
        /// <param name="result"></param>
        public ContextCondition(ICondition condition, bool result)
        {
            if (condition == null) {
                throw new ArgumentNullException();
            }
            _condition = condition;
            _result = result;
        }

        #region IContextCondition implementation
        public ICondition Condition
        {
            get
            {
                return _condition;
            }
        }

        public bool Result
        {
            get
            {
                return _result;
            }
            set
            {
                _result = value;
            }
        }
        #endregion
    }
}
