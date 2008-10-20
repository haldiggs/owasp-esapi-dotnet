/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/.NET_ESAPI.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using System.Collections;
using HttpInterfaces;
using System.Web;

namespace Owasp.Esapi.Interfaces
{
	/// <summary> The IUser interface represents an application user or user account. There is quite a lot of information that an
	/// application must store for each user in order to enforce security properly. There are also many rules that govern
	/// authentication and identity management.
	/// [P]
	/// [img src="doc-files/Authenticator.jpg" height="600">
	/// [P]
	/// A user account can be in one of several states. When first created, a User should be disabled, not expired, and
	/// unlocked. To start using the account, an administrator should enable the account. The account can be locked for a
	/// number of reasons, most commonly because they have failed login for too many times. Finally, the account can expire
	/// after the expiration date has been reached. The User must be enabled, not expired, and unlocked in order to pass
	/// authentication.
	/// 
	/// </summary>
    /// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <created>  2008 </created>

    public interface IUser
    {       
        /// <summary>
        /// Account name, or user name, for user.
        /// </summary>
        string AccountName
        {
            get;

            set;

        }
        /// <summary> 
        /// The CSRF token.        
        /// </summary>        
        string CsrfToken
        {
            get;

        }
        /// <summary> The number of failed login attempts since the last successful login for an account. This property is
        /// intended to be used as a part of the account lockout feature, to help protect against brute force attacks.
        /// However, the implementor should be aware that lockouts can be used to prevent access to an application by a
        /// legitimate user, and should consider the risk of denial of service.
        /// </summary>
        int FailedLoginCount
        {
            get;

        }
        /// <summary> 
        /// The remember token.
        /// </summary>
        string RememberToken
        {
            get;

        }
        /// <summary> 
        /// The roles for the user.
        /// </summary>
        ArrayList Roles
        {
            get;

            set;

        }

        /// <summary> 
        /// The screen name
        /// </summary>
        string ScreenName
        {
            get;

            set;

        }
        /// <summary> 
        /// Whether or not the user is anonymous.
        /// </summary>
        bool Anonymous
        {
            get;

        }
        /// <summary> 
        /// Whether or not the users account is disabled.
        /// </summary>
        bool Enabled
        {
            get;

        }
        /// <summary> 
        /// Whether or not the users account is expired.
        /// </summary>
        bool Expired
        {
            get;

        }
        /// <summary> 
        /// Whether or not the users account is locked        
        /// </summary>
        bool Locked
        {
            get;

        }
        /// <summary>
        /// Whether or not the user is logged in.
        /// </summary>
        bool LoggedIn
        {
            get;

        }

        /// <summary> 
        /// Gets the time when the users account will expire.        
        /// </summary>
        DateTime ExpirationTime
        {
            get;
            set;
        }

        /// <summary> 
        /// Adds a role to an account.
        /// </summary>
        /// <param name="role">The role to add.
        /// </param>        
        void AddRole(string role);

        /// <summary> 
        /// Adds a list of roles.        
        /// </summary>
        /// <param name="newRoles">The roles to add.
        /// </param>        
        void AddRoles(ArrayList newRoles);

        /// <summary> Sets the user's password, performing a verification of the user's old password, the equality of the two new
        /// passwords, and the strength of the new password.
        /// </summary>
        /// <param name="oldPassword">The old password.
        /// </param>
        /// <param name="newPassword1">The new password.
        /// </param>
        /// <param name="newPassword2">The confirmation of the new password.
        /// </param>        
        void ChangePassword(string oldPassword, string newPassword1, string newPassword2);

        /// <summary> 
        /// Disables the users account.
        /// </summary>        
        void Disable();

        /// <summary> 
        /// Enables the users account.        
        /// </summary>        
        void Enable();

        /// <summary> 
        /// Returns the last host address used by the user. This will be used in any log messages generated by the processing
        /// of this request.
        /// </summary>
        /// <returns>
        /// Value of last host address used by user.
        /// </returns>
        string GetLastHostAddress();

        /// <summary> 
        /// Returns the date of the last failed login time for a user. This date should be used in a message to users after a
        /// successful login, to notify them of potential attack activity on their account.        
        /// </summary>
        /// <returns> 
        /// Date of the last failed login.
        /// </returns>       
        DateTime GetLastFailedLoginTime();

        /// <summary> 
        /// Returns the date of the last successful login time for a user. This date should be used in a message to users
        /// after a successful login, to notify them of potential attack activity on their account.        
        /// </summary>
        /// <returns> 
        /// Date of the last successful login.
        /// </returns>
        DateTime GetLastLoginTime();

        /// <summary> 
        /// Returns the last password change time.        
        /// </summary>
        /// <returns> The last password change time.
        /// </returns>
        DateTime GetLastPasswordChangeTime();

        /// <summary> 
        /// Increments the failed login count for the user.
        /// </summary>        
        void IncrementFailedLoginCount();

        /// <summary> 
        /// Checks if an account has been assigned a particular role.        
        /// </summary>
        /// <param name="role">
        /// The role to check.
        /// </param>
        /// <returns>
        /// true, if is user in role.        
        /// </returns>
        bool IsInRole(string role);

        /// <summary> 
        /// Returns true if the request is the first one of a new login session. This is intended to be used as a flag to
        /// display a message about the user's last successful login time.        
        /// </summary>
        /// <returns>
        /// true, if this is the first request of a new login session.
        /// </returns>
        bool IsFirstRequest();

        /// <summary> 
        /// Tests to see if the user's session has exceeded the absolute time out.        
        /// </summary>
        /// <returns> 
        /// true, if users session has exceeded the absolute time out.
        /// </returns>
        bool IsSessionAbsoluteTimeout();

        /// <summary> 
        /// Tests to see if the user's session has timed out from inactivity.        
        /// </summary>
        /// <returns> 
        /// true, if the users session has timed out from inactivity.
        /// </returns>
        bool IsSessionTimeout();

        /// <summary> Locks the users account.</summary>
        void Lock();

        /// <summary> Logout this user.</summary>
        void Logout();

        /// <summary> 
        /// Removes a role from an account.        
        /// </summary>
        /// <param name="role">The role to remove.
        /// </param>
        void RemoveRole(string role);

        /// <summary> 
        /// Returns a token to be used as a prevention against CSRF attacks. This token should be added to all links and
        /// forms. The application should verify that all requests contain the token, or they may have been generated by a
        /// CSRF attack. It is generally best to perform the check in a centralized location, either a filter or controller.
        /// See the VerifyCSRFToken method.        
        /// </summary>
        /// <returns> The CSRF token.
        /// </returns>        
        string ResetCsrfToken();

        /// <summary> 
        /// Returns a token to be used as a "remember me" cookie. The cookie is not seen by the user and can be fairly long,
        /// at least 20 digits is suggested to prevent brute force attacks. See LoginWithRememberToken.        
        /// </summary>
        /// <returns> The remember token.
        /// </returns>        
        string ResetRememberToken();

        /// <summary> Unlocks the users account.</summary>
        void Unlock();

        /// <summary>
        /// Verifies the password is correct.
        /// </summary>
        /// <param name="password">The password to verify.</param>
        /// <returns>true, if the password is correct.</returns>
        bool VerifyPassword(string password);

        /// <summary>
        /// Authenticates the user with a given password.
        /// </summary>
        /// <param name="password">The password to use for authentication.</param>
        void LoginWithPassword(string password);        
    }
}
