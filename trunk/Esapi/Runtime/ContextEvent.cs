using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Runtime context
    /// </summary>
    internal class ContextEvent
    {
        private EvaluationCache<ICondition, bool> _conditionValueCache;
        private string _currentEvent;

        /// <summary>
        /// Initialize context
        /// </summary>
        /// <param name="currentEvent">Current event name</param>
        public ContextEvent(string currentEvent)
        {
            _currentEvent = currentEvent;
            _conditionValueCache = new EvaluationCache<ICondition, bool>();
        }

        /// <summary>
        /// Condition evaluation cache
        /// </summary>
        public EvaluationCache<ICondition, bool> ConditionValueCache
        {
            get { return _conditionValueCache; }
        }

        /// <summary>
        /// Current event name
        /// </summary>
        public string CurrentEvent
        {
            get { return _currentEvent; }
        }
    }

}
