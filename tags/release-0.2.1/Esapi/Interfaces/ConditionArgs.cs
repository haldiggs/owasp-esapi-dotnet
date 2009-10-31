using System;

namespace Owasp.Esapi.Interfaces
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
        public static readonly ConditionArgs Empty;

        static ConditionArgs()
        {
            Empty = new ConditionArgs();
        }
    }
}
