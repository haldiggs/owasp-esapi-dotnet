using System;
using System.Text.RegularExpressions;

namespace Owasp.Esapi.IntrusionDetection.Conditions
{
    /// <summary>
    /// Regex based URL context condition
    /// </summary>
    public class UrlCondition : IContextCondition
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

        #region IContextSelector Members

        /// <summary>
        /// Verify URL condition
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public bool Evaluate(ContextConditionArgs args)
        {
            if (args == null) {
                throw new ArgumentNullException();
            }

            return _url.IsMatch(args.RequestUri.ToString());
        }

        #endregion
    }
}
