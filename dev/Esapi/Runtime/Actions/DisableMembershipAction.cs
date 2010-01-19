using System;
using System.Web.Security;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Runtime;

namespace Owasp.Esapi.Runtime.Actions
{
    /// <summary>
    /// Disable Membership User
    /// </summary>
    [Action(BuiltinActions.MembershipDisable)]
    public class DisableMembershipAction : IAction
    {
        #region IAction Members
        /// <summary>
        /// Disable current MembershipUser
        /// </summary>
        /// <param name="args">Action arguments</param>
        public void Execute(ActionArgs args)
        {
            MembershipUser user = Membership.GetUser();
            if (user != null) {
                user.IsApproved = false;
                Membership.UpdateUser(user);
            }
        }

        #endregion
    }
}
