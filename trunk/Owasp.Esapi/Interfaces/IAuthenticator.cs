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

namespace Owasp.Esapi.Interfaces
{
    /// <summary> The IAuthenticator interface defines a set of methods for generating and
    /// handling account credentials and session identifiers. The goal of this
    /// interface is to encourage developers to protect credentials from disclosure
    /// to the maximum extent possible.    
    /// 
    /// Once possible implementation relies on the use of a thread local variable to
    /// store the current user's identity. The application is responsible for calling
    /// SetCurrentUser() as soon as possible after each HTTP request is received. The
    /// value of GetCurrentUser() is used in several other places in this API. This
    /// eliminates the need to pass a user object to methods throughout the library.
    /// For example, all of the logging, access control, and exception calls need
    /// access to the currently logged in user.
    /// 
    /// The goal is to minimize the responsibility of the developer for
    /// authentication. In this example, the user simply calls authenticate with the
    /// current request and the name of the parameters containing the username and
    /// password. The implementation should verify the password if necessary, create
    /// a session if necessary, and set the user as the current user.
    /// 
    /// try {
    /// Esapi.Authenticator().Authenticate(request, response, username, password);
    /// // continue with authenticated user
    /// } catch (AuthenticationException e) {
    /// // handle failed authentication (it's already been logged)
    /// }
    /// 
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    
    public interface IAuthenticator
    {
        /// <summary> Gets all the user names.
        /// 
        /// </summary>
        /// <returns> The user names, as a list.
        /// </returns>
        IList GetUserNames();

        /// <summary> Authenticates the user's credentials from the HttpRequest if
        /// necessary, creates a session if necessary, and sets the user as the
        /// current user.
        /// </summary>
        /// <returns> The User object, if the login attempt was successful.
        /// </returns>
        IUser Login();

        /// <summary> Creates a user.
        /// 
        /// </summary>
        /// <param name="accountName">The account name for the user.
        /// </param>
        /// <param name="password1">The password for the user.
        /// </param>
        /// <param name="password2">A confirmation of the password for the user.
        /// 
        /// </param>
        /// <returns> The new User object.
        /// 
        /// </returns>
        IUser CreateUser(string accountName, string password1, string password2);

        /// <summary> Generates a cryptographically strong password.
        /// 
        /// </summary>
        /// <returns>The cryptographically strong password.
        /// </returns>
        string GenerateStrongPassword();

        /// <summary> Generates a strong password, different fromt the previous password.
        /// 
        /// </summary>
        /// <param name="oldPassword">The old password for the user.
        /// </param>
        /// <param name="user">The user to set the password for.
        /// 
        /// </param>
        /// <returns> The cryptographically strong password.
        /// </returns>
        string GenerateStrongPassword(string oldPassword, IUser user);

        /// <summary> Returns the User matching the provided accountName.
        /// 
        /// </summary>
        /// <param name="accountName">The account name to match.
        /// 
        /// </param>
        /// <returns> The matching User object, or null if no match exists.
        /// </returns>
        IUser GetUser(string accountName);

        /// <summary> Returns the currently logged in User.
        /// 
        /// </summary>
        /// <returns> The matching User object, or the Anonymous user if no match
        /// exists.
        /// </returns>
        IUser GetCurrentUser();

        /// <summary> Sets the currently logged in User.
        /// 
        /// </summary>
        /// <param name="user">The current user.
        /// </param>
        void SetCurrentUser(IUser user);

        /// <summary> Returns a string representation of the hashed password, using the
        /// accountName as the salt. The salt helps to prevent against "rainbow"
        /// table attacks where the attacker pre-calculates hashes for known strings.
        /// 
        /// </summary>
        /// <param name="password">The password.
        /// </param>
        /// <param name="accountName">The account name.
        /// 
        /// </param>
        /// <returns> The hashed password.
        /// </returns>
        string HashPassword(string password, string accountName);

        /// <summary> Removes the account for the list of available account.
        /// 
        /// </summary>
        /// <param name="accountName">The account name for the account to remove.
        /// 
        /// </param>
        void RemoveUser(string accountName);

        /// <summary> Validates the strength of the account name.
        /// 
        /// </summary>
        /// <param name="accountName">The account name to validate the strength of.
        /// 
        /// </param>
        /// <returns> true, if the account name has sufficient strength.
        /// 
        /// </returns>
        void VerifyAccountNameStrength(string accountName);

        /// <summary> Validates the strength of the password.
        /// 
        /// </summary>
        /// <param name="oldPassword">The old password.
        /// </param>
        /// <param name="newPassword">The new password.
        /// 
        /// </param>
        /// <returns> true, if the password has sufficient strength.
        /// 
        /// </returns>
        void VerifyPasswordStrength(string oldPassword, string newPassword);

        /// <summary> Verifies the account exists.
        /// 
        /// </summary>
        /// <param name="accountName">The account name to check.
        /// 
        /// </param>
        /// <returns> true, if the account exists.
        /// </returns>
        bool Exists(string accountName);

        /// <summary>
        /// Gets the user from the current session.
        /// </summary>
        /// <param name="request">The current HTTP request.</param>
        /// <returns>The current user.</returns>
        IUser GetUserFromSession(IHttpRequest request);
    }
}
