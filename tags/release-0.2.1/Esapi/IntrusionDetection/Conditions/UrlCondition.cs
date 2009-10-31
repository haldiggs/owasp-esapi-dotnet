using System;
using System.Text.RegularExpressions;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.IntrusionDetection.Conditions
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

            IntrusionConditionArgs intrusionArgs = (IntrusionConditionArgs)args;
            return _url.IsMatch(intrusionArgs.RequestUri.ToString());
        }

        #endregion
    }
}
