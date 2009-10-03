using System.Text;
using System.Text.RegularExpressions;

namespace Owasp.Esapi
{
    /// <summary>
    /// Match helper
    /// </summary>
    internal class MatchHelper
    {
        /// <summary>
        /// Convert wildcard match string to a regex
        /// </summary>
        /// <param name="wildcardMatch">Wildcard string</param>
        /// <returns></returns>
        internal static Regex WildcardToRegex(string wildcardMatch)
        {
            StringBuilder sbRegex = new StringBuilder();
            sbRegex.Append("^");

            if (!string.IsNullOrEmpty(wildcardMatch)) {
                foreach (char w in wildcardMatch) {
                    if (w == '*') {
                        sbRegex.Append(".*");
                        continue;
                    }
                    if (w == '?') {
                        sbRegex.Append(".");
                        continue;
                    }
                    sbRegex.Append(Regex.Escape(w.ToString()));
                }
            }

            sbRegex.Append("$");

            return new Regex(sbRegex.ToString());
        }
    }
}
