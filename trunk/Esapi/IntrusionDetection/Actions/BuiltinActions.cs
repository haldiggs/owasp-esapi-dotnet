
namespace Owasp.Esapi.IntrusionDetection.Actions
{
    /// <summary>
    /// ESAPI builtin intrusion detection actions
    /// </summary>
    public static class BuiltinActions
    {
        /// <summary>
        /// Log action
        /// </summary>
        public const string Log = "BuiltinActions.Log";

        /// <summary>
        /// Disable ASP.NET Membership account
        /// </summary>
        public const string MembershipDisable = "BuiltinActions.MembershipDisable";

        /// <summary>
        /// Do Forms authentication logout
        /// </summary>
        public const string FormsAuthenticationLogout = "BuiltinActions.FormsAuthenticationLogout";
    }
}
