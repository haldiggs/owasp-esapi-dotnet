using System;
using System.Web;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Runtime;

namespace Owasp.Esapi.Runtime.Actions
{
    /// <summary>
    /// Redirect request
    /// </summary>
    [Action(BuiltinActions.Redirect, AutoLoad = false)]
    internal class RedirectAction : IAction
    {
        private string _url;

        /// <summary>
        /// Initialize redirect action
        /// </summary>
        /// <param name="url">Url to redirect to</param>
        public RedirectAction(string url)
        {
            if (string.IsNullOrEmpty(url)) {
                throw new ArgumentException();
            }

            _url = url;
        }

        /// <summary>
        /// Redirect URL
        /// </summary>
        public string Url
        {
            get { return _url; }
            set
            {
                if (string.IsNullOrEmpty(value)) {
                    throw new ArgumentNullException();
                }
                _url = value;
            }
        }

        #region IAction Members

        /// <summary>
        /// Execute redirect action 
        /// </summary>
        /// <param name="args"></param>
        /// <remarks>Will terminate the current request</remarks>
        public void Execute(ActionArgs args)
        {
            HttpResponse response = (HttpContext.Current != null ? HttpContext.Current.Response : null);
            if (response == null) {
                throw new InvalidOperationException();
            }


            response.Redirect(_url, true);
        }

        #endregion
    }
}
