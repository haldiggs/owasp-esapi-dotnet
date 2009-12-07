using System;

namespace Owasp.Esapi.Runtime
{

    /// <summary>
    /// ESAPI condition arguments
    /// </summary>
    [Serializable]
    public class ConditionArgs
    {
        /// <summary>
        /// Empty condition arguments
        /// </summary>
        public readonly static ConditionArgs Emtpy = new ConditionArgs();

        private RuntimeEventArgs _runtimeEventArgs;

        public ConditionArgs()
        {
        }
        /// <summary>
        /// Runtime event arguments
        /// </summary>
        public RuntimeEventArgs RuntimeArgs
        {
            get { return _runtimeEventArgs; }
            internal set { _runtimeEventArgs = value; }
        }
    }
}
