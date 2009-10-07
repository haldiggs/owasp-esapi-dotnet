using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// Rule base interface
    /// </summary>
    public interface IRule
    {
        /// <summary>
        /// Process rule
        /// </summary>
        /// <param name="args">Rule arguments</param>
        void Process(RuleArgs args);
    }
}
