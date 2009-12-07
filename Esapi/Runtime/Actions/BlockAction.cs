using System;
using System.Web;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Runtime;

namespace Owasp.Esapi.Runtime.Actions
{
    /// <summary>
    /// Block current request action
    /// </summary>
    [Action(BuiltinActions.Block)]
    public class BlockAction : IAction
    {
        private int _statusCode = 403; //Forbidden

        /// <summary>
        /// Block HTTP status code
        /// </summary>
        public int StatusCode
        {
            get { return _statusCode;  }
            set { _statusCode = value; }
        }

        #region IAction Members

        /// <summary>
        /// Block current request
        /// </summary>
        /// <param name="args"></param>
        /// <remarks>Will end the current request</remarks>
        public void Execute(ActionArgs args)
        {
            HttpResponse response = (HttpContext.Current != null ? HttpContext.Current.Response : null);

            if (null == response) {
                throw new InvalidOperationException();
            }

            response.ClearHeaders();
            response.ClearContent();

            response.StatusCode = _statusCode;
            response.End();
        }

        #endregion
    }
}
