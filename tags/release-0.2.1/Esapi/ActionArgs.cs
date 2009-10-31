using System;

namespace Owasp.Esapi
{
    /// <summary>
    /// ESAPI action arguments
    /// </summary>
    [Serializable]
    public class ActionArgs
    {
        /// <summary>
        /// Empty action arguments
        /// </summary>
        public static readonly ActionArgs Empty;

        static ActionArgs()
        {
            Empty = new ActionArgs();
        }
    }
}
