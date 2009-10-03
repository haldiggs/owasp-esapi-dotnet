namespace Owasp.Esapi.IntrusionDetection.Rules
{
    /// <summary>
    /// Intrusion detection CSRF rule
    /// </summary>
    public class CsrfRule : IInstrusionInputRule, IIntrusionOutputRule
    {
        #region IInstrusionInputRule Members

        /// <summary>
        /// Verify CSRF token
        /// </summary>
        /// <param name="args"></param>
        public void Process(IntrusionInputRuleArgs args)
        {
            Esapi.HttpUtilities.VerifyCsrfToken();
        }

        #endregion

        #region IIntrusionOutputRule Members

        /// <summary>
        /// Add CSRF token
        /// </summary>
        /// <param name="args"></param>
        public void Process(IntrusionOutputRuleArgs args)
        {
            Esapi.HttpUtilities.AddCsrfToken();
        }

        #endregion
    }
}
