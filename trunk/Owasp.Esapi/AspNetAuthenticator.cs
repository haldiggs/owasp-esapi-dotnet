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
using System.Collections.Generic;
using System.Text;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Errors;
using System.Web.Security;
using System.Collections;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of IAuthenticator for ASP.NET applications that uses the Membership API
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=.NET+ESAPI question">Alex Smolen</a> at <a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> November 5, 2008
    /// </since>

    class AspNetAuthenticator : Authenticator
    {
        public new IUser CreateUser(string accountName, string password1, string password2)
        {
            if (accountName == null || password1 == null || password2 == null)
            {
                throw new AuthenticationAccountsException("Account creation failed", "Attempt to create user with null accountName or password");
            }
            if (password1.Equals(password2))
            {
                try
                {
                    Membership.CreateUser(accountName, password1);
                }
                catch (AuthenticationException ae)
                {
                    throw new AuthenticationException("Account creation failed", "Error in Membership API", ae);
                }
                logger.Fatal(LogEventTypes.SECURITY, "New user created: " + accountName);
                return new AspNetUser(Membership.GetUser(accountName));
            }
            return null;
        }

        /// <summary>
        /// Returns the currently logged user as set by the SetCurrentUser() methods.  Uses the Membership API. 
        /// Must not log in this method because the logger calls GetCurrentUser() and this could cause a loop.
        /// </summary>
        /// <returns>The current User object.</returns>
        public new IUser GetCurrentUser()
        {
            return new AspNetUser(Membership.GetUser());
        }


        /// <summary> Returns the User matching the provided accountName. Uses the Membership API.
        /// 
        /// </summary>
        /// <param name="accountName">The account name to match.
        /// 
        /// </param>
        /// <returns> The matching User object, or null if no match exists.
        /// </returns>
        public new IUser GetUser(string accountName)
        {
            return new AspNetUser(Membership.GetUser(accountName));
        }

        /// <summary> Removes the account for the list of available account.
        /// 
        /// </summary>
        /// <param name="accountName">The account name for the account to remove.
        /// </param>
        public new void RemoveUser(string accountName)
        {
            if (!Membership.DeleteUser(accountName))
            {
                throw new AuthenticationAccountsException("Remove user failed", "Can't remove invalid accountName " + accountName);
            }                           
            logger.Fatal(LogEventTypes.SECURITY, "User " + accountName + " removed");
        }
        
        /// <summary> This method should be called for every HTTP request, to login the current user either from the session of HTTP
        /// request. This method will set the current user so that GetCurrentUser() will work properly. This method also
        /// checks that the user's access is still enabled, unlocked, and unexpired before allowing login. For convenience
        /// this method also returns the current user.
        /// 
        /// </summary>
        /// <returns> The current user.
        /// </returns>
        public new IUser Login()
        {
            return new AspNetUser(Membership.GetUser());
        }

        /// <summary> Log out the current user.</summary>
        public new void Logout()
        {
            FormsAuthentication.SignOut();
        }

        /// <summary> Sets the currently logged in User.
        /// 
        /// </summary>
        public new void SetCurrentUser(IUser user)
        {
            
        }

        /// <summary> Gets all the user names. Uses the Membership API.
        /// 
        /// </summary>
        /// <returns> The user names, as a list.
        /// </returns> 
        public new IList GetUserNames()
        {
            ArrayList usernames = new ArrayList();
            foreach (User user in Membership.GetAllUsers())
            {
                usernames.Add(user.AccountName);
            }
            return usernames;         
        }
        
    }
}
