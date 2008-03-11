/// <summary> OWASP Enterprise Security API .NET (ESAPI.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using System.Collections;
using Owasp.Esapi.Interfaces;
using HttpInterfaces;
using System.Web;
using System.IO;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the IAuthenticator interface. This reference implementation is backed by a simple text
    /// file that contains serialized information about users. Many organizations will want to create their own
    /// implementation of the methods provided in the IAuthenticator interface backed by their own user repository. This
    /// reference implementation captures information about users in a simple text file format that contains user information
    /// separated by the pipe "|" character. Here's an example of a single line from the users.txt file:
    /// 
    /// <PRE>
    /// 
    /// account name | hashed password | roles | lockout | status | remember token | old password hashes | last
    /// hostname | last change | last login | last failed | expiration | failed
    /// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// mitch | 44k/NAzQUlrCq9musTGGkcMNmdzEGJ8w8qZTLzpxLuQ= | admin,user | unlocked | enabled | token |
    /// u10dW4vTo3ZkoM5xP+blayWCz7KdPKyKUojOn9GJobg= | 192.168.1.255 | 1187201000926 | 1187200991568 | 1187200605330 |
    /// 2187200605330 | 1
    /// 
    /// </PRE>
    /// 
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=ESAPI.NET question">Alex Smolen</a> at <a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator">
    /// </seealso> 
   
    public class Authenticator: IAuthenticator
    {

        /// <summary>
        /// Static constructor.
        /// </summary>
        static Authenticator()
        {
            logger = Logger.GetLogger("ESAPI", "Authenticator");
        }

        /// <summary> Public constructor for the authenticator class.
        /// 
        /// </summary>        
        public Authenticator()
        {
        }
        

        // FIXME: ENHANCE consider an impersonation feature


        /// <summary>This field is the key for the User object in the HttpContext.Items collection</summary>
        protected internal const string USER = "ESAPIUserContextKey";

		/// <summary>The logger. </summary>
        private static readonly Logger logger;

        /// <summary>The anonymous user </summary>
        // FIXME: AAA is this whole anonymous user concept right?
        internal IUser anonymous = new User("anonymous", "anonymous");

		/// <summary>The file that contains the user db </summary>
		private FileInfo userDB = null;
		
		/// <summary>How frequently to check the user db for external modifications </summary>
		private long checkInterval = 60 * 1000;
		
		/// <summary>The last modified time we saw on the user db. </summary>
		private long lastModified = 0;
		
		/// <summary>The last time we checked if the user db had been modified externally. </summary>
		private long lastChecked = 0;

        /// <summary>The user map. </summary>        
        private IDictionary userMap = new Hashtable();


        private IHttpContext context;

        /// <summary>
        /// The context for the authentication.
        /// 
        /// Instead of using the C#/.NET equivalent of Java's ThreadLocal, the ThreadStatic attribute, the ESAPI.NET
        /// library makes use of the HttpContext class to provide per-request storage. This is designed for this
        /// type of usage, while the ThreadStatic attribute is potentially dangerous in ASP.NET, which is thread
        /// agile, meaning threads may switch during processing.
        /// 
        /// http://www.hanselman.com/blog/ATaleOfTwoTechniquesTheThreadStaticAttributeAndSystemWebHttpContextCurrentItems.aspx
        /// 
        /// </summary>
        public IHttpContext Context
        {
            get
            {
                return context;
            }
            set
            {
                context = value;
            }
        }

        /// <summary>
        /// The current HTTP request. This is only valid when the context has been set.
        /// </summary>
        public IHttpRequest CurrentRequest
        {
            get
            {
                return (Context == null ? null : Context.Request);
            }

        }

        /// <summary>
        /// The current HTTP response. This is only valid when the context has been set.
        /// </summary>
        public IHttpResponse CurrentResponse
        {
            get
            {
                return (Context == null ? null : Context.Response);
            }

        }

        /// <summary>
        /// The current HTTP session. This is only valid when the context has been set.
        /// </summary>
        public IHttpSession CurrentSession
        {
            get
            {
                return (Context == null ? null : Context.Session);
            }

        }


        /// <summary> Fail safe main program to add or update an account in an emergency.
        /// [P]
        /// Warning: this method does not perform the level of validation and checks
        /// generally required in ESAPI, and can therefore be used to create a username and password that do not comply
        /// with the username and password strength requirements.
        /// [/P]
        /// Example: Use this to add the alice account with the admin role to the users file: 
        /// [PRE]
        /// TODO - Fix
        /// Update Esapi.config file config section esapi/authentication
        /// 
        /// [/PRE]
        /// 
        /// </summary>
        /// <param name="args">The arguments for the main method (standard).
        /// </param>
        [STAThread]
        public static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                System.Console.Out.WriteLine("Usage: Authenticator accountname password role");
                return;
            }
            Authenticator auth = new Authenticator();
            string accountName = args[0].ToLower();
            string password = args[1];
            string role = args[2];
            User user = (User) auth.GetUser(args[0]);
            if (user == null)
            {
                user = new User();
                user.AccountName = accountName;
                auth.userMap[accountName] = user;
                logger.LogCritical(ILogger_Fields.SECURITY, "New user created: " + accountName);
            }
            string newHash = auth.HashPassword(password, accountName);
            user.SetHashedPassword(newHash);
            user.AddRole(role);
            user.Enable();
            user.Unlock();
            auth.SaveUsers();
            long ticks_two = auth.lastModified;
            long ticks = auth.userDB.LastWriteTime.Ticks;
            System.Console.Out.WriteLine("User account " + user.AccountName + " updated");
        }

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
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.CreateUser(string, string, string)">
        /// </seealso>
        public IUser CreateUser(string accountName, string password1, string password2)
        {
            lock (this)
            {
                LoadUsersIfNecessary();
                if (accountName == null)
                {
                    throw new AuthenticationAccountsException("Account creation failed", "Attempt to create user with null accountName");
                }
                if (userMap.Contains(accountName.ToLower()))
                {
                    throw new AuthenticationAccountsException("Account creation failed", "Duplicate user creation denied for " + accountName);
                }
                IUser user = new User(accountName, password1, password2);
                userMap[accountName.ToLower()] = user;
                logger.LogCritical(ILogger_Fields.SECURITY, "New user created: " + accountName);
                SaveUsers();
                return user;
            }
        }

        /// <summary> Verifies the account exists.
        /// 
        /// </summary>
        /// <param name="accountName">The account name to check.
        /// 
        /// </param>
        /// <returns> true, if the account exists.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.Exists(string)">
        /// </seealso>
        public bool Exists(string accountName)
        {
            IUser user = GetUser(accountName);
            return (user != null);
        }


        /// <summary> Generates a strong password.
        /// 
        /// </summary>
        /// <returns> The cryptographically strong password.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.GenerateStrongPassword()">
        /// </seealso>
        public virtual String GenerateStrongPassword()
        {
            return GenerateStrongPassword("");
        }

        /// <summary> Generates a strong password, different from the previous password.
        /// 
        /// </summary>
        /// <param name="oldPassword">The old password for the user.
        /// </param>
        /// <returns> The cryptographically strong password.
        /// </returns>
        private string GenerateStrongPassword(string oldPassword)
        {
            IRandomizer r = Esapi.Randomizer();
            string newPassword = "";
            int limit = 10;
            for (int i = 0; i < limit; i++)
            {
                try
                {
                    newPassword = r.GetRandomString(8, Encoder.CHAR_PASSWORD);
                    VerifyPasswordStrength(newPassword, oldPassword);
                    return newPassword;
                }
                catch (AuthenticationException e)
                {
                    logger.LogDebug(ILogger_Fields.SECURITY, "Password generator created weak password: " + newPassword + ". Regenerating.", e);
                }
            }
            logger.LogCritical(ILogger_Fields.SECURITY, "Strong password generation failed after  " + limit + " attempts");
            return null;
        }


        /// <summary> Generates a strong password, different from the previous password.
        /// 
        /// </summary>
        /// <param name="oldPassword">The old password for the user.
        /// </param>
        /// <param name="user">The user to set the password for.
        /// 
        /// </param>
        /// <returns> The cryptographically strong password.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.GenerateStrongPassword(string, IUser)">
        /// </seealso>
        public string GenerateStrongPassword(string oldPassword, IUser user)
        {
            string newPassword = GenerateStrongPassword(oldPassword);
            if (newPassword != null)
            {
                logger.LogCritical(ILogger_Fields.SECURITY, "Generated strong password for " + user.AccountName);
            }
            return newPassword;
        }
        
        /// <summary>
        /// Returns the currently logged user as set by the SetCurrentUser() methods. Must not log in this method because the
        /// logger calls GetCurrentUser() and this could cause a loop.
        /// </summary>
        /// <returns>The current User object.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.GetCurrentUser()">
        /// </seealso>
        public IUser GetCurrentUser()
        {
            if (Context == null)
            {
                return anonymous;
            }
            IUser currentUser = (IUser) Context.Items[USER];
            if (currentUser == null)
            {
                return anonymous;
            }
            return currentUser;
        }


        /// <summary> Returns the User matching the provided accountName.
        /// 
        /// </summary>
        /// <param name="accountName">The account name to match.
        /// 
        /// </param>
        /// <returns> The matching User object, or null if no match exists.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.GetUser(string)">
        /// </seealso>
        public IUser GetUser(string accountName)
        {
            lock (this)
            {
                LoadUsersIfNecessary();
                IUser user = (IUser) userMap[accountName.ToLower()];
                return user;
            }
        }

        /// <summary>
        /// Gets the user from the current session.
        /// </summary>
        /// <param name="request">The current HTTP request.</param>
        /// <returns>The current user.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.GetUserFromSession(IHttpRequest)">
        /// </seealso>
        public IUser GetUserFromSession(IHttpRequest request)
        {            
            IHttpSession session = CurrentSession;
            if (session != null)
            {
                string userName = (string)session[USER];
                if (userName != null)
                {
                    IUser sessionUser = this.GetUser(userName);
                    if (sessionUser != null)
                    {
                        SetCurrentUser(sessionUser);
                        return sessionUser;
                    }
                }
            }
            return null;
        }

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
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.HashPassword(string, string)">
        /// </seealso>
        public string HashPassword(string password, string accountName)
        {
            string salt = accountName.ToLower();
            return Esapi.Encryptor().Hash(password, salt);
        }

        /// <summary> Removes the account for the list of available account.
        /// 
        /// </summary>
        /// <param name="accountName">The account name for the account to remove.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.RemoveUser(string)">
        /// </seealso>
        public void RemoveUser(string accountName)
        {
            lock (this)
            {
                LoadUsersIfNecessary();
                IUser user = GetUser(accountName);
                if (user == null)
                {
                    throw new AuthenticationAccountsException("Remove user failed", "Can't remove invalid accountName " + accountName);
                }
                userMap.Remove(accountName.ToLower());
                // Beware - the logging engine might reload inadvertently reload the user file before the save completes, overwriting the change!
                SaveUsers();
                logger.LogCritical(ILogger_Fields.SECURITY, "User " + accountName + " removed");
            }
        }

        /// <summary> Validates the strength of the password.         
        /// This implementation checks: - for any 3 character substrings of the old password - for use of a length * 
        /// character sets > 16 (where character sets are upper, lower, digit, and special characters).
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
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.VerifyPasswordStrength(string, string)">
        /// </seealso>
        public void VerifyPasswordStrength(string newPassword, string oldPassword)
        {
            string oPassword = (oldPassword == null) ? "" : oldPassword;

            // can't change to a password that contains any 3 character substring of old password
            int length = oPassword.Length;
            for (int i = 0; i < length - 2; i++)
            {
                string sub = oPassword.Substring(i, (i + 3) - (i));
                if (newPassword.IndexOf(sub) > -1)
                    throw new AuthenticationCredentialsException("Invalid password", "New password cannot contain pieces of old password");
            }

            // new password must have enough character sets and length
            int charsets = 0;
            for (int i = 0; i < newPassword.Length; i++)
            {
                if (Array.BinarySearch(Encoder.CHAR_LOWERS, newPassword[i]) > 0)
                {
                    charsets++;
                    break;
                }
            }
            for (int i = 0; i < newPassword.Length; i++)
            {
                if (Array.BinarySearch(Encoder.CHAR_UPPERS, newPassword[i]) > 0)
                {
                    charsets++;
                    break;
                }
            }
            for (int i = 0; i < newPassword.Length; i++)
            {
                if (Array.BinarySearch(Encoder.CHAR_DIGITS, newPassword[i]) > 0)
                {
                    charsets++;
                    break;
                }
            }
            for (int i = 0; i < newPassword.Length; i++)
            {
                if (Array.BinarySearch(Encoder.CHAR_SPECIALS, newPassword[i]) > 0)
                {
                    charsets++;
                    break;
                }
            }
            int strength = newPassword.Length * charsets;
            if (strength < 16)
            {
                throw new AuthenticationCredentialsException("Invalid password", "New password is not long and complex enough");
            }
        }


        /// <summary> This method should be called for every HTTP request, to login the current user either from the session of HTTP
        /// request. This method will set the current user so that GetCurrentUser() will work properly. This method also
        /// checks that the user's access is still enabled, unlocked, and unexpired before allowing login. For convenience
        /// this method also returns the current user.
        /// 
        /// </summary>
        /// <returns> The current user.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.Login()">
        /// </seealso>
        public IUser Login()
        {
            IHttpRequest request = Context.Request;
            IHttpResponse response = Context.Response;

            // save the current request and response in the threadlocal variables            
            if (!Esapi.HttpUtilities().SecureChannel)
            {
                new AuthenticationCredentialsException("Session exposed", "Authentication attempt made over non-SSL connection. Check web.xml and server configuration");
            }
            User user = (User) null;

            // if there's a user in the session then set that and quit
            user = (User) GetUserFromSession(request);

            if (user != null)
            {
                user.SetLastHostAddress(request.UserHostAddress);
                user.SetFirstRequest(false);
            }
            else
            {
                // try to verify credentials
                user = (User) LoginWithUsernameAndPassword(request, response);
                user.SetFirstRequest(true);
            }

            // don't let anonyous user log in
            if (user.Anonymous)
            {
                throw new AuthenticationLoginException("Login failed", "Anonymous user cannot be set to current user");
            }

            // don't let disabled users log in
            if (!user.Enabled)
            {
                DateTime tempAux = DateTime.Now;                
                user.SetLastFailedLoginTime(tempAux);
                throw new AuthenticationLoginException("Login failed", "Disabled user cannot be set to current user: " + user.AccountName);
            }

            // don't let locked users log in
            if (user.Locked)
            {
                DateTime tempAux2 = DateTime.Now;                
                user.SetLastFailedLoginTime(tempAux2);
                throw new AuthenticationLoginException("Login failed", "Locked user cannot be set to current user: " + user.AccountName);
            }

            // don't let expired users log in
            if (user.Expired)
            {
                DateTime tempAux3 = DateTime.Now;                
                user.SetLastFailedLoginTime(tempAux3);
                throw new AuthenticationLoginException("Login failed", "Expired user cannot be set to current user: " + user.AccountName);
            }
            SetCurrentUser(user);
            return user;
        }


        /// <summary>
        /// Gets the user from the current session.
        /// </summary>
        /// <param name="request">The current HTTP request.</param>
        /// <returns>The current user.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.GetUserFromSession(IHttpRequest)">
        /// </seealso>
        public IUser GetUserFromSession(HttpRequest request)
        {
            return GetUserFromSession(WebContext.Cast(request));
        }


        /// <summary> Log out the current user.</summary>
        public void Logout()
        {
            IUser user = GetCurrentUser();
            user.Logout();
        }


        /// <summary> Sets the currently logged in User.
        /// 
        /// </summary>
        /// <param name="user">The current user.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.SetCurrentUser(IUser)">
        /// </seealso>
        public void SetCurrentUser(IUser user)
        {
            Context.Items[USER] = user;
        }
     
        /// <summary> Validates the strength of the account name.
        /// This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a
		/// brute force attack, however the real strength comes from the name length and complexity.
        /// 
        /// </summary>
        /// <param name="context">The context for the verification.
        /// </param>
        /// <param name="newAccountName">The account name to validate the strength of.
        /// 
        /// </param>
        /// <returns> true, if the account name has sufficient strength.
        /// 
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.VerifyAccountNameStrength(string, string)">
        /// </seealso>
        public void VerifyAccountNameStrength(string context, string newAccountName)
        {
            if (newAccountName == null)
            {
                throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account with a null account name");
            }
            // FIXME: ENHANCE make the lengths configurable?
            if (!Esapi.Validator().IsValidDataFromBrowser(context, "AccountName", newAccountName))
            {
                throw new AuthenticationCredentialsException("Invalid account name", "New account name is not valid: " + newAccountName);
            }
        }

        /// <summary> Gets all the user names.
        /// 
        /// </summary>
        /// <returns> The user names, as a list.
        /// </returns> 
        /// <seealso cref="Owasp.Esapi.Interfaces.IAuthenticator.GetUserNames()">
        /// </seealso>
        public IList GetUserNames()
        {
            lock (this)
            {
                LoadUsersIfNecessary();                
                return new ArrayList(userMap.Keys);
            }
        }


        /// <summary> Loads the users from a file.
        /// 
        /// </summary>
        protected internal void LoadUsersIfNecessary()
        {
            string ResourceDirectory = ((SecurityConfiguration)Esapi.SecurityConfiguration()).ResourceDirectory.FullName;
            userDB = new FileInfo(ResourceDirectory+"\\" + "users.txt");
            long now = (DateTime.Now.Ticks);
            // We only check at most every checkInterval milliseconds
            if (now - lastChecked < checkInterval)
            {
                return;
            }
            lastChecked = now;
            
            long lastModified = userDB.LastWriteTime.Ticks;
            if (this.lastModified == lastModified)
            {
                return;
            }
            // file was touched so reload it
            lock (this)
            {
                logger.LogTrace(ILogger_Fields.SECURITY, "Loading users from " + userDB.FullName, null);

                // FIXME: AAA Necessary?
                // add the Anonymous user to the database
                // map.put(anonymous.getAccountName(), anonymous);

                StreamReader reader = null;
                try
                {                    
                    Hashtable map = new Hashtable();
                    reader = new StreamReader(userDB.FullName, System.Text.Encoding.Default);
                    string line = null;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.Length > 0 && line[0] != '#')
                        {
                            IUser user = new User(line);
                            if (!user.AccountName.Equals("anonymous"))
                            {
                                if (map.ContainsKey(user.AccountName))
                                {
                                    logger.LogCritical(ILogger_Fields.SECURITY, "Problem in user file. Skipping duplicate user: " + user, null);
                                }
                                map[user.AccountName] = user;
                            }
                        }                        
                    }
                    userMap = map;
                    this.lastModified = lastModified;
                    logger.LogTrace(ILogger_Fields.SECURITY, "User file reloaded: " + map.Count, null);
                }
                catch (System.Exception e)
                {
                    logger.LogCritical(ILogger_Fields.SECURITY, "Failure loading user file: " + userDB.FullName, e);
                }
                finally
                {
                    try
                    {
                        if (reader != null)
                        {
                            reader.Close();
                        }
                    }
                    catch (IOException e)
                    {
                        logger.LogCritical(ILogger_Fields.SECURITY, "Failure closing user file: " + userDB.FullName, e);
                    }
                }
            }
        }
 
        /// <summary> Saves the user database to the file system. In this implementation you must call save to commit any changes to
        /// the user file. Otherwise changes will be lost when the program ends.
        /// 
        /// </summary>
        public void SaveUsers()
        {
            lock (this)
            {
                StreamWriter writer = null;
                try
                {
                    writer = new StreamWriter(userDB.FullName, false, System.Text.Encoding.Default);
                    writer.WriteLine("# This is the user file associated with the ESAPI library from http://www.owasp.org");
                    writer.WriteLine("# accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
                    writer.WriteLine();
                    SaveUsers(writer);
                    writer.Flush();
                    logger.LogCritical(ILogger_Fields.SECURITY, "User file written to disk");
                }
                catch (IOException e)
                {
                    logger.LogCritical(ILogger_Fields.SECURITY, "Problem saving user file " + userDB.FullName, e);
                    throw new AuthenticationException("Internal Error", "Problem saving user file " + userDB.FullName, e);
                }
                finally
                {
                    if (writer != null)
                    {
                        writer.Close();                        
                        lastModified = userDB.LastWriteTime.Ticks;
                        lastChecked = lastModified;
                    }
                }
            }
        }

        /// <summary> Save users to a stream.
        /// 
        /// </summary>
        /// <param name="writer">The stream writer to write to.
        /// </param>
        internal void SaveUsers(StreamWriter writer)
        {
            lock (this)
            {
                IEnumerator i = GetUserNames().GetEnumerator();                
                while (i.MoveNext())
                {                    
                    string accountName = (string)i.Current;
                    User u = (User) GetUser(accountName);
                    if (u != null && !u.Anonymous)
                    {
                        writer.WriteLine(u.Save());
                    }
                    else
                    {
                        new AuthenticationCredentialsException("Problem saving user", "Skipping save of user " + accountName);
                    }
                }
                logger.LogTrace(ILogger_Fields.SECURITY, "User file updated", null);
            }
        }


        /// <summary> Utility method to extract credentials and verify them.
        /// 
        /// </summary>
        /// <param name="request">
        /// The current request object.
        /// </param>
        /// <param name="response">
        /// The current response object.
        /// </param>
        /// <returns>
        /// The authenticated user, if the username and password are correct. null, otherwise.
        /// </returns>
        private IUser LoginWithUsernameAndPassword(IHttpRequest request, IHttpResponse response)
        {

            // FIXME: AAA the login path should also be a configuration - this
            // should check (if loginrequest && parameters then do
            // loginWithPassword)
            
            string username = request[Esapi.SecurityConfiguration().UsernameParameterName];            
            string password = request[Esapi.SecurityConfiguration().PasswordParameterName];

            // if a logged-in user is requesting to login, log them out first
            IUser user = GetCurrentUser();
            if (user != null && !user.Anonymous)
            {
                logger.LogWarning(ILogger_Fields.SECURITY, "User requested relogin. Performing logout then authentication");
                user.Logout();
            }

            // now authenticate with username and password
            if (username == null || password == null)
            {
                if (username == null)
                {
                    username = "unspecified user";
                }
                throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed for " + username + " because of null username or password");
            }
            user = GetUser(username);
            if (user == null)
            {
                throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed because user " + username + " doesn't exist");
            }
            user.LoginWithPassword(password);
            return user;
        }
    }
}
