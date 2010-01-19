using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Evaluation cache
    /// </summary>
    internal class EvaluationCache<TKey, TValue>
    {
        private Dictionary<TKey, TValue> _values;

        /// <summary>
        /// Initialize cache
        /// </summary>
        public EvaluationCache()
        {
            _values = new Dictionary<TKey, TValue>();
        }

        /// <summary>
        /// Get cached value
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns>True if found, false otherwise</returns>
        public bool TryGetValue(TKey key, out TValue value)
        {
            return _values.TryGetValue(key, out value);
        }

        /// <summary>
        /// Cache value
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        public void SetValue(TKey key, TValue value)
        {
            _values[key] = value;
        }
    }
}
