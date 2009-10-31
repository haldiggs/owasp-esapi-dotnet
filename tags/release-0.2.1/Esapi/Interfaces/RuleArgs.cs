using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// ESAPI ruule arguments
    /// </summary>
    [Serializable]
    public class RuleArgs
    {
        /// <summary>
        /// Empty rule arguments
        /// </summary>
        public static readonly RuleArgs Empty;

        static RuleArgs()
        {
            Empty = new RuleArgs();
        }
    }
}
