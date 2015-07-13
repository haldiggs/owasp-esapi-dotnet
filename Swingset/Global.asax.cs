using System;
using Owasp.Esapi.Runtime;
using Owasp.Esapi.Runtime.Rules;
using Owasp.Esapi.Runtime.Actions;
using System.Web.UI.WebControls;
using System.Web.Security;
using System.Net;

namespace Owasp.Esapi.Swingset
{
	/// <summary>
	/// Make sure no logged-on user exceeds the max number of requests 
	/// </summary>
	[RunRule(typeof(RequestThrottleRule), new Type[] { typeof(LogAction), typeof(LogoutAction)})]
	public class Global : System.Web.HttpApplication
	{
		public enum AppRoles { Admin, User };
		public const string AdminUserName = "admin";
		public const string passWord = "P@ssw0rd!";


		protected void Application_Start(object sender, EventArgs e)
		{
			//just for testing... I would never do this
			CheckRoles();

			string msg = "";
			MembershipUser user = Membership.GetUser(AdminUserName);
			if (user == null)
			{
				MembershipCreateStatus membershipCreateStatus;
				user = Membership.CreateUser(AdminUserName, passWord, "someuser@nowhere.com", "what is my name", AdminUserName, true, out membershipCreateStatus);
				switch (membershipCreateStatus)
				{
					case MembershipCreateStatus.DuplicateEmail:
						goto default;
					case MembershipCreateStatus.DuplicateProviderUserKey:
						goto default;
					case MembershipCreateStatus.DuplicateUserName:
						goto default;
					case MembershipCreateStatus.InvalidAnswer:
						goto default;
					case MembershipCreateStatus.InvalidEmail:
						goto default;
					case MembershipCreateStatus.InvalidPassword:
						goto default;
					case MembershipCreateStatus.InvalidProviderUserKey:
						goto default;
					case MembershipCreateStatus.InvalidQuestion:
						goto default;
					case MembershipCreateStatus.InvalidUserName:
						goto default;
					case MembershipCreateStatus.ProviderError:
						goto default;
					case MembershipCreateStatus.UserRejected:
						goto default;
					case MembershipCreateStatus.Success:
						msg = "Account status: " + membershipCreateStatus.ToString();
						if (!Roles.IsUserInRole(AdminUserName, AppRoles.Admin.ToString()))
							Roles.AddUserToRole(AdminUserName, AppRoles.Admin.ToString());
						user.Comment = "Vendor Account. Please do not delete.";
						user.IsApproved = true;
						Membership.UpdateUser(user);
						break;
					default:
						msg = "Internal Admin account creation issue: " + Environment.NewLine + membershipCreateStatus.ToString() + Environment.NewLine +
							"Check the source code of this projects global.asax";
						Exception ex = new Exception(WebUtility.HtmlDecode(msg));
						throw ex;
				}

			}
		}

		private void CheckRoles()
		{
			if (!Roles.RoleExists(AppRoles.Admin.ToString()))
				Roles.CreateRole(AppRoles.Admin.ToString());
			if (!Roles.RoleExists(AppRoles.User.ToString()))
				Roles.CreateRole(AppRoles.User.ToString());
		}

		protected void Session_Start(object sender, EventArgs e)
		{

		}

		protected void Application_BeginRequest(object sender, EventArgs e)
		{

		}

		protected void Application_AuthenticateRequest(object sender, EventArgs e)
		{

		}

		protected void Application_Error(object sender, EventArgs e)
		{
			Exception ex = Server.GetLastError();
			while (ex != null && ex.InnerException != null)
			{
				ex = ex.InnerException;
			}
			Esapi.Logger.Error(LogEventTypes.FUNCTIONALITY, "Unspecified top-level error occured", ex);
			Response.Redirect("~/Error.aspx");            
		}

		protected void Session_End(object sender, EventArgs e)
		{

		}

		protected void Application_End(object sender, EventArgs e)
		{

		}
	}
}