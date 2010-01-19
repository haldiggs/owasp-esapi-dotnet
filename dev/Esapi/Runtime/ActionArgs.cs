using System;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// ESAPI action arguments
    /// </summary>
    [Serializable]
    public class ActionArgs
    {
        /// <summary>
        /// Emtpy action arguments
        /// </summary>
        public readonly static ActionArgs Empty = new ActionArgs();

        private RuntimeEventArgs _runtimeEventArgs;
        private IRule _faultingRule;
        private Exception _faultException;

        public ActionArgs()
        {
        }

        /// <summary>
        /// Faulting rule
        /// </summary>
        public IRule FaultingRule
        {
            get { return _faultingRule; }
            internal set { _faultingRule = value; }
        }
        /// <summary>
        /// Fault exception 
        /// </summary>
        public Exception FaultException
        {
            get { return _faultException; }
            internal set { _faultException = value; }
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
