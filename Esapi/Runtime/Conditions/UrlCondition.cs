using System;
using System.Text.RegularExpressions;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Runtime;
using System.Web;

namespace Owasp.Esapi.Runtime.Conditions
{
    /// <summary>
    /// Regex based URL context condition
    /// </summary>
    public class UrlCondition : ICondition
    {
        /// <summary>
        /// Any URL pattern
        /// </summary>
        private const string AnyUrlPattern = "*";

        private Regex _url;

        /// <summary>
        /// Intialize URL condition
        /// </summary>
        /// <param name="urlPattern">URL Pattern</param>
        public UrlCondition(string urlPattern)
        {
            UrlPattern = urlPattern;
        }

        /// <summary>
        /// URL pattern
        /// </summary>
        public string UrlPattern
        {
            get { return _url.ToString(); }
            set
            {
                if (string.IsNullOrEmpty(value)) {
                    _url = new Regex("^$");
                }
                else {
                    _url = new Regex(value);
                }
            }
                
        }

        #region ICondition Members

        /// <summary>
        /// Verify URL condition
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public bool Evaluate(ConditionArgs args)
        {
            if (args == null) {
                throw new ArgumentNullException();
            }
            

            HttpRequest request = HttpContext.Current != null ? HttpContext.Current.Request : null;
            if (request != null) {
                return _url.IsMatch(request.Url.ToString());
            }
            return false;
        }

        #endregion
    }
}
