using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace Owasp.Esapi.Runtime.Conditions
{
    /// <summary>
    /// Handler match condition
    /// </summary>
    public class HandlerCondition : ICondition
    {
        private Type _handlerType;

        /// <summary>
        /// Initialize handler condition
        /// </summary>
        public HandlerCondition()
        {
            _handlerType = null;
        }
        /// <summary>
        /// Initialize handler condition
        /// </summary>
        /// <param name="handlerType">Handler type to match</param>
        public HandlerCondition(Type handlerType)
        {
            if (handlerType == null) {
                throw new ArgumentNullException();
            }
            _handlerType = handlerType;
        }

        /// <summary>
        /// Handler type to match
        /// </summary>
        public Type HandlerType
        {
            get { return _handlerType; }
            set { _handlerType = value; }
        }

        #region ICondition Members
        /// <summary>
        /// Evaluate handler condition
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public bool Evaluate(ConditionArgs args)
        {
            bool isMatch = false;

            IHttpHandler handler = (HttpContext.Current != null ?
                                        HttpContext.Current.CurrentHandler :
                                        null);

            if (handler != null && _handlerType != null) {
                isMatch = handler.GetType().Equals(_handlerType);
            }

            return isMatch;
        }

        #endregion
    }
}
