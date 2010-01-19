
namespace Owasp.Esapi.Runtime.Actions
{
    /// <summary>
    /// ESAPI builtin intrusion detection actions
    /// </summary>
    public static class BuiltinActions
    {
        /// <summary>
        /// Log action
        /// </summary>
        public const string Log = "Log";

        /// <summary>
        /// Disable ASP.NET Membership account
        /// </summary>
        public const string MembershipDisable = "MembershipDisable";

        /// <summary>
        /// Do Forms authentication logout
        /// </summary>
        public const string FormsAuthenticationLogout = "FormsAuthenticationLogout";

        /// <summary>
        /// Block HTTP request
        /// </summary>
        public const string Block = "Block";

        /// <summary>
        /// Redirect user to page
        /// </summary>
        public const string Redirect = "Redirect";

        /// <summary>
        /// Transfer user to page
        /// </summary>
        public const string Transfer = "Transfer";
    }
}
