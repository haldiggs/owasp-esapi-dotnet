using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Owasp.Esapi.IntrusionDetection
{
    /// <summary>
    /// Intrusion input rule
    /// </summary>
    public interface IInstrusionInputRule
    {
        /// <summary>
        /// Process input rule arguments
        /// </summary>
        /// <param name="args"></param>
        void Process(IntrusionInputRuleArgs args);
    }

    /// <summary>
    /// Intrusion output rule 
    /// </summary>
    public interface IIntrusionOutputRule
    {
        /// <summary>
        /// Process output rule arguments
        /// </summary>
        /// <param name="args"></param>
        void Process(IntrusionOutputRuleArgs args);
    }
}
