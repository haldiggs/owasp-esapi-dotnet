/// <summary> OWASP Enterprise Security API .NET (Esapi.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (Esapi) project. For details, please see
/// http://www.owasp.org/Esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The Esapi is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using Owasp.Esapi.Interfaces;
using System.Collections;
using System.Web.SessionState;
using System.Web;
using HttpInterfaces;
using System.Text.RegularExpressions;
using Owasp.Esapi.Errors;
using System.Text;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the IUser interface. This implementation is serialized into a flat file in a simple format.
    /// 
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=Esapi.NET question">Alex Smolen</a> at <a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IUser">
    /// </seealso>
    
    public class User : IUser
    {
        /// <summary>
        /// Account name, or user name, for user.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.AccountName">
        /// </seealso>
        public string AccountName
        {
            get
            {
                return accountName;
            }

            set
            {
                string old = value;
                this.accountName = value.ToLower();
                logger.LogCritical(ILogger_Fields.SECURITY, "Account name changed from " + old + " to " + AccountName);
            }

        }
        /// <summary> 
        /// The CSRF token.        
        /// </summary>     
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.CsrfToken">
        /// </seealso>
        public string CsrfToken
        {
            get
            {
                return csrfToken;
            }
        }

        /// <summary> 
        /// Gets the time when the users account will expire.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.ExpirationTime">
        /// </seealso>
        public DateTime ExpirationTime
        {
            get
            {                
                return expirationTime;
            }

            set
            {
                this.expirationTime = new DateTime(value.Ticks);             
                logger.LogCritical(ILogger_Fields.SECURITY, "Account expiration time set to " + value.ToString("r") + " for " + AccountName);
            }

        }
        /// <summary> 
        /// The number of failed login attempts since the last successful login for an account. This property is
        /// intended to be used as a part of the account lockout feature, to help protect against brute force attacks.
        /// However, the implementor should be aware that lockouts can be used to prevent access to an application by a
        /// legitimate user, and should consider the risk of denial of service.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.FailedLoginCount">
        /// </seealso>
        public int FailedLoginCount
        {
            get
            {
                return failedLoginCount;
            }

        }

        /// <summary> 
        /// The remember token.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.RememberToken">
        /// </seealso>
        public string RememberToken
        {
            get
            {
                return rememberToken;
            }

        }

        /// <summary> 
        /// The roles for the user.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Roles">
        /// </seealso>
        public ArrayList Roles
        {
            get
            {
                return ArrayList.ReadOnly(roles);
            }

            set
            {                
                this.roles = new ArrayList();
                AddRoles(value);
                logger.LogCritical(ILogger_Fields.SECURITY, "Adding roles " + value.ToString() + " to " + AccountName);
            }
        }

        /// <summary> 
        /// The screen name
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.ScreenName">
        /// </seealso>
        public string ScreenName
        {

            get
            {
                return screenName;
            }                        

            set
            {
                this.screenName = value;
                logger.LogCritical(ILogger_Fields.SECURITY, "ScreenName changed to " + value + " for " + AccountName);
            }

        }

        /// <summary> 
        /// Whether or not the user is anonymous.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Anonymous">
        /// </seealso>
        public bool Anonymous
        {
            get
            {
                return AccountName.Equals("anonymous");
            }

        }

        /// <summary> 
        /// Whether or not the users account is disabled.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Enabled">
        /// </seealso>
        public bool Enabled
        {
            get
            {
                return enabled;
            }

        }

        /// <summary> 
        /// Whether or not the users account is expired.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Expired">
        /// </seealso>
        public bool Expired
        {
            get
            {
                return (ExpirationTime < DateTime.Now);

                // FIXME: ENHANCE should expiration happen automatically?  Or based on lastPasswordChangeTime?
                //		long from = lastPasswordChangeTime.getTime();
                //		long to = new Date().getTime();
                //		double difference = to - from;
                //		long days = Math.round((difference / (1000 * 60 * 60 * 24)));
                //		return days > 60;
            }

        }

        /// <summary> 
        /// Whether or not the users account is locked        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Locked">
        /// </seealso>
        public bool Locked
        {

            get
            {
                return locked;
            }

        }

        /// <summary>
        /// Whether or not the user is logged in.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.LoggedIn">
        /// </seealso>
        public bool LoggedIn
        {

            get
            {
                return loggedIn;
            }

        }


        /// <summary>The Constant serialVersionUID. </summary>
        private const long serialVersionUID = 1L;

        /// <summary>The logger. </summary>
        private static readonly Logger logger;

        /// <summary>true, only for the first HTTP request, false afterwards. </summary>
        private bool isFirstRequest = true;

        /// <summary>The account name. </summary>
        private string accountName = "";

        /// <summary>The screen name. </summary>
        private string screenName = "";

        /// <summary>The hashed password. </summary>
        private string hashedPassword = "";

        /// <summary>The old password hashes. </summary>
        private IList oldPasswordHashes = new ArrayList();

        /// <summary>The remember token. </summary>
        private string rememberToken = "";

        /// <summary>The CSRF token. </summary>
        private string csrfToken = "";

        /// <summary>The roles. </summary>        
        private ArrayList roles = new ArrayList();

        /// <summary>Is user locked. </summary>
        private bool locked = false;

        /// <summary>Is user logged in. </summary>
        private bool loggedIn = true;

        /// <summary>Is user enabled. </summary>
        private bool enabled = false;

        /// <summary>The last host address used. </summary>
        // Note: This was changed because of null reference exception during testing.
        private string lastHostAddress = "";

        /// <summary>The last password change time. </summary>
        private DateTime lastPasswordChangeTime = DateTime.Now;

        /// <summary>The last login time. </summary>
        private DateTime lastLoginTime = DateTime.Now;

        /// <summary>The last failed login time. </summary>
        private DateTime lastFailedLoginTime = DateTime.Now;

        /// <summary>The expiration time. </summary>        
        private DateTime expirationTime = DateTime.MaxValue;

        /// <summary>A flag to indicate that the password must be changed before the account can be used. </summary>
        // FIXME: ENHANCE enable this required password change feature?
        // private boolean requiresPasswordChange = true;

        /// <summary>The failed login count. </summary>
        private int failedLoginCount = 0;

        /// <summary>Intrusion detection events. </summary>        
        private IDictionary events = new Hashtable();


        // FIXME: ENHANCE consider adding these for access control support
        //
        //private String authenticationMethod = null;
        //
        //private String connectionChannel = null;

        /// <summary> Instantiates a new user.</summary>
        protected internal User()
        {
            // hidden
        }

        /// <summary> 
        /// Instantiates a new user.        
        /// </summary>
        /// <param name="line">
        /// The line from a file to instantiate the new user.
        /// </param>
        protected internal User(string line)
        {
            string[] parts = Regex.Split(line, "\\|");
            this.accountName = parts[0].Trim().ToLower();
            // FIXME: AAA validate account name
            this.hashedPassword = parts[1].Trim();

            this.roles = new ArrayList(Regex.Split(parts[2].Trim().ToLower(), " *, *"));
            this.locked = !"unlocked".ToUpper().Equals(parts[3].Trim().ToUpper());
            this.enabled = "enabled".ToUpper().Equals(parts[4].Trim().ToUpper());
            this.rememberToken = parts[5].Trim();

            // generate a new Csrf token
            this.ResetCsrfToken();

            this.oldPasswordHashes = new ArrayList(Regex.Split(parts[6].Trim(), " *, *"));
            this.lastHostAddress = parts[7].Trim();            
            this.lastPasswordChangeTime = new DateTime(Int64.Parse(parts[8].Trim()));            
            this.lastLoginTime = new DateTime(Int64.Parse(parts[9].Trim()));            
            this.lastFailedLoginTime = new DateTime(Int64.Parse(parts[10].Trim()));            
            this.expirationTime = new DateTime(Int64.Parse(parts[11].Trim()));
            this.failedLoginCount = Int32.Parse(parts[12].Trim());
        }

        /// <summary> 
        /// Constructor only for use in creating the Anonymous user.        
        /// </summary>
        /// <param name="accountName">
        /// The account name for the user.
        /// </param>
        /// <param name="password">
        /// The password for the user.
        /// </param>
        protected internal User(string accountName, string password)
        {
            this.accountName = accountName.ToLower();
        }

        /// <summary> 
        /// Instantiates a new user.        
        /// </summary>
        /// <param name="accountName">
        /// The account name for the user.
        /// </param>
        /// <param name="password1">
        /// The password for the user.
        /// </param>
        /// <param name="password2">
        /// The confirmation password for the user.        
        /// </param>        
        public User(string accountName, string password1, string password2)
        {

            Esapi.Authenticator().VerifyAccountNameStrength("Create User", accountName);

            if (password1 == null)
            {
                throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account " + accountName + " with a null password");
            }
            Esapi.Authenticator().VerifyPasswordStrength(password1, null);

            if (!password1.Equals(password2))
                throw new AuthenticationCredentialsException("Passwords do not match", "Passwords for " + accountName + " do not match");

            this.accountName = accountName.ToLower();
            try
            {
                SetHashedPassword(Esapi.Encryptor().Hash(password1, this.accountName));
            }
            catch (EncryptionException ee)
            {
                throw new AuthenticationException("Internal error", "Error hashing password for " + this.accountName, ee);
            }            
            expirationTime = new DateTime(DateTime.Now.Ticks + (1000L * 60 * 60 * 24 * 90)); // 90 days
            logger.LogCritical(ILogger_Fields.SECURITY, "Account created successfully: " + accountName);
        }

        /// <summary> 
        /// Adds a role to an account.
        /// </summary>
        /// <param name="role">The role to add.
        /// </param>    
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.AddRole(string)">
        /// </seealso>
        public void AddRole(string role)
        {
            string roleName = role.ToLower();
            if (Esapi.Validator().IsValidDataFromBrowser("addRole", "RoleName", roleName))
            {
                roles.Add(roleName);
                logger.LogCritical(ILogger_Fields.SECURITY, "Role " + roleName + " added to " + AccountName);
            }
            else
            {
                throw new AuthenticationAccountsException("Add role failed", "Attempt to add invalid role " + roleName + " to " + AccountName);
            }
        }

        /// <summary> 
        /// Adds a list of roles.        
        /// </summary>
        /// <param name="newRoles">
        /// The roles to add.
        /// </param>  
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.AddRoles(ArrayList)">
        /// </seealso>
        public void AddRoles(ArrayList newRoles)
        {
            IEnumerator i = newRoles.GetEnumerator();            
            while (i.MoveNext())
            {                
                AddRole((string)i.Current);
            }
        }

        /// <summary> 
        /// Adds a security event to the user.        
        /// </summary>
        /// <param name="eventName">
        /// The security event to add.
        /// </param>
        public void AddSecurityEvent(string eventName)
        {
            Event securityEvent = (Event)events[eventName];
            if (securityEvent == null)
            {
                securityEvent = new Event(eventName);
                events[eventName] = securityEvent;
            }

            Threshold q = Esapi.SecurityConfiguration().GetQuota(eventName);
            if (q.Count > 0)
            {
                securityEvent.Increment(q.Count, q.Interval);
            }
        }

        // FIXME: ENHANCE - make admin only methods separate from public API
        /// <summary> Sets the user's password. This is an admin-only method.
        /// </summary>        
        /// <param name="newPassword1">The new password.
        /// </param>
        /// <param name="newPassword2">The confirmation of the new password.
        /// </param> 
        protected internal void ChangePassword(string newPassword1, string newPassword2)
        {
            SetLastPasswordChangeTime(DateTime.Now);
            string newHash = Esapi.Authenticator().HashPassword(newPassword1, AccountName);
            SetHashedPassword(newHash);
            logger.LogCritical(ILogger_Fields.SECURITY, "Password changed for user: " + AccountName);
        }

        /// <summary> Sets the user's password, performing a verification of the user's old password, the equality of the two new
        /// passwords, and the strength of the new password.
        /// </summary>
        /// <param name="oldPassword">The old password.
        /// </param>
        /// <param name="newPassword1">The new password.
        /// </param>
        /// <param name="newPassword2">The confirmation of the new password.
        /// </param> 
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.ChangePassword(string, string, string)">
        /// </seealso>
        public void ChangePassword(string oldPassword, string newPassword1, string newPassword2)
        {
            if (!hashedPassword.Equals(Esapi.Authenticator().HashPassword(oldPassword, AccountName)))
            {
                throw new AuthenticationCredentialsException("Password change failed", "Authentication failed for password chanage on user: " + AccountName);
            }
            if (newPassword1 == null || newPassword2 == null || !newPassword1.Equals(newPassword2))
            {
                throw new AuthenticationCredentialsException("Password change failed", "Passwords do not match for password change on user: " + AccountName);
            }
            Esapi.Authenticator().VerifyPasswordStrength(newPassword1, oldPassword);
            SetLastPasswordChangeTime(DateTime.Now);
            string newHash = Esapi.Authenticator().HashPassword(newPassword1, accountName);
            if (oldPasswordHashes.Contains(newHash))
            {
                throw new AuthenticationCredentialsException("Password change failed", "Password change matches a recent password for user: " + AccountName);
            }
            SetHashedPassword(newHash);
            logger.LogCritical(ILogger_Fields.SECURITY, "Password changed for user: " + AccountName);
        }


        /// <summary> 
        /// Disables the users account.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Disable()">
        /// </seealso>
        public void Disable()
        {
            // FIXME: ENHANCE what about disabling for a short time period - to address DOS attack?
            enabled = false;
            logger.LogSpecial("Account disabled: " + AccountName, null);
        }

        // Note: Do I need this in C# implementation?
        /// <summary> 
        /// Dump a collection as a comma-separated list.
        /// </summary>
        /// <returns> 
        /// The string representation of the list.
        /// </returns>
        protected internal string Dump(ICollection c)
        {
            StringBuilder sb = new StringBuilder();
            IEnumerator i = c.GetEnumerator();            
            while (i.MoveNext())
            {                
                string s = (string)i.Current;
                sb.Append(s);
                if (i.MoveNext())
                {
                    sb.Append(",");
                }
            }
            return sb.ToString();
        }

        /// <summary> 
        /// Enables the users account.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Enable()">
        /// </seealso>
        public void Enable()
        {
            this.enabled = true;
            logger.LogSpecial("Account enabled: " + AccountName, null);
        }

        /// <summary>
        /// Checks equality based on account name
        /// </summary>
        /// <param name="obj">Object to compare.</param>
        /// <returns>true, if users have the same account name.</returns>
        public override bool Equals(Object obj)
        {
            if (this == obj)
            {
                return true;
            }
            if (obj == null)
            {
                return false;
            }
            if (!GetType().Equals(obj.GetType()))
            {
                return false;
            }             
            User other = (User)obj;
            return accountName.Equals(other.accountName);
        }

        /// <summary>
        /// Returns the date of the last failed login time for a user. This date should be used in a message to users after a
        /// successful login, to notify them of potential attack activity on their account.        
        /// </summary>
        /// <returns>
        /// Date of the last failed login.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.GetLastFailedLoginTime()">
        /// </seealso>
        public DateTime GetLastFailedLoginTime()
        {   
            // Note: Do we need to clone here?
            return lastFailedLoginTime;
        }


        /// <summary> 
        /// Returns the last host address used by the user. This will be used in any log messages generated by the processing
        /// of this request.
        /// </summary>
        /// <returns>
        /// Value of last host address used by user.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.GetLastHostAddress()">
        /// </seealso>
        public string GetLastHostAddress()
        {
            IHttpRequest request = ((Authenticator)Esapi.Authenticator()).CurrentRequest;
            if (request != null)
            {
                SetLastHostAddress(request.UserHostAddress);
            }
            return lastHostAddress;
        }

        /// <summary> 
        /// Returns the date of the last successful login time for a user. This date should be used in a message to users
        /// after a successful login, to notify them of potential attack activity on their account.        
        /// </summary>
        /// <returns> 
        /// Date of the last successful login.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.GetLastLoginTime()">
        /// </seealso>
        public DateTime GetLastLoginTime()
        {         
            // Note: Do we need to clone here?
            return lastLoginTime;
        }

        /// <summary> 
        /// Returns the last password change time.        
        /// </summary>
        /// <returns> The last password change time.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.GetLastPasswordChangeTime()">
        /// </seealso>
        public DateTime GetLastPasswordChangeTime()
        {            
            // Note: Do we need to clone here?
            return lastPasswordChangeTime;
        }

        /// <summary>
        /// Gets the hash code for this object based on the account name.
        /// </summary>
        /// <returns>The hash code based on the account name for this user.</returns>
        public override int GetHashCode()
        {
            return accountName.GetHashCode();
        }

        /// <summary> 
        /// Increments the failed login count for the user.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.IncrementFailedLoginCount()">
        /// </seealso>
        public void IncrementFailedLoginCount()
        {
            failedLoginCount++;
        }

        /// <summary> 
        /// Checks if an account has been assigned a particular role.        
        /// </summary>
        /// <param name="role">
        /// The role to check.
        /// </param>
        /// <returns>
        /// true, if is user in role.        
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.IsInRole(string)">
        /// </seealso>
        public bool IsInRole(string role)
        {
            return roles.Contains(role.ToLower());
        }

        /// <summary> 
        /// Tests to see if the user's session has exceeded the absolute time out.        
        /// </summary>
        /// <param name="session">
        /// The users session.
        /// </param>
        /// <returns> 
        /// true, if users session has exceeded the absolute time out.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.IsSessionAbsoluteTimeout(IHttpSession)">
        /// </seealso>
        public bool IsSessionAbsoluteTimeout(IHttpSession session)
        {
            // TODO: We can't really figure out when the session was created, from the ASP.NET API
            DateTime deadline = new DateTime(DateTime.Now.Ticks + 1000 * 60 * 60 * 2);
            DateTime now = DateTime.Now;
            return (now > deadline);
        }

        /// <summary> 
        /// Tests to see if the user's session has timed out from inactivity.        
        /// </summary>
        /// <param name="session">
        /// The users session
        /// </param>
        /// <returns> 
        /// true, if the users session has timed out from inactivity.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.IsSessionTimeout(IHttpSession)">
        /// </seealso>
        public bool IsSessionTimeout(IHttpSession session)
        {            
            // TODO: We can't figure out when it is was last accessed either.
            DateTime deadline = new DateTime(DateTime.Now.Ticks + 1000 * 60 * 20);
            DateTime now = DateTime.Now;
            return (now > deadline);
        }

        /// <summary> Locks the users account.</summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Lock()">
        /// </seealso>
        public void Lock()
        {
            this.locked = true;
            logger.LogCritical(ILogger_Fields.SECURITY, "Account locked: " + AccountName);
        }

        /// <summary>
        /// Authenticates the user with a given password.
        /// </summary>
        /// <param name="password">The password to use for authentication.</param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.LoginWithPassword(string)">
        /// </seealso>
        public void LoginWithPassword(string password)
        {
            if (password == null || password.Equals(""))
            {                
                SetLastFailedLoginTime(DateTime.Now);
                throw new AuthenticationLoginException("Login failed", "Missing password: " + accountName);
            }

            // don't let disabled users log in
            if (!Enabled)
            {
                SetLastFailedLoginTime(DateTime.Now);
                throw new AuthenticationLoginException("Login failed", "Disabled user attempt to login: " + accountName);
            }

            // don't let locked users log in
            if (Locked)
            {
                SetLastFailedLoginTime(DateTime.Now);
                throw new AuthenticationLoginException("Login failed", "Locked user attempt to login: " + accountName);
            }

            // don't let expired users log in
            if (Expired)
            {
                SetLastFailedLoginTime(DateTime.Now);
                throw new AuthenticationLoginException("Login failed", "Expired user attempt to login: " + accountName);
            }

            // if there is a user already logged in, log them out and then authenticate the new user
            if (!Anonymous)
            {
                Logout();
            }

            try
            {
                if (VerifyPassword(password))
                {
                    // FIXME: AAA verify loggedIn is properly maintained
                    loggedIn = true;
                    IHttpSession session = ((HttpUtilities)Esapi.HttpUtilities()).ChangeSessionIdentifier();
                    session.Add(Authenticator.USER, AccountName);
                    Esapi.Authenticator().SetCurrentUser(this);                                      
                    SetLastLoginTime(DateTime.Now);
                    SetLastHostAddress(((Authenticator)Esapi.Authenticator()).CurrentRequest.UserHostAddress);
                    logger.LogTrace(ILogger_Fields.SECURITY, "User logged in: " + accountName);
                }
                else
                {
                    throw new AuthenticationLoginException("Login failed", "Login attempt as " + AccountName + " failed");
                }
            }
            catch (EncryptionException ee)
            {
                throw new AuthenticationException("Internal error", "Error verifying password for " + accountName, ee);
            }
        }



        /// <summary> Logout this user.</summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Logout()">
        /// </seealso>
        public void Logout()
        {
            Authenticator authenticator = ((Authenticator)Esapi.Authenticator());
            if (!authenticator.GetCurrentUser().Anonymous)
            {
                IHttpRequest request = authenticator.CurrentRequest;
                IHttpSession session = authenticator.Context.Session;
                if (session != null)
                {                    
                    session.Abandon();
                }
                // TODO - Kill the correct cookie
                Esapi.HttpUtilities().KillCookie("ASPSESSIONID");
                loggedIn = false;
                logger.LogSuccess(ILogger_Fields.SECURITY, "Logout successful");
                authenticator.SetCurrentUser(authenticator.anonymous);
            }
        }

        /// <summary> 
        /// Removes a role from an account.        
        /// </summary>
        /// <param name="role">The role to remove.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.RemoveRole(string)">
        /// </seealso>
        public void RemoveRole(string role)
        {
            roles.Remove(role.ToLower());
            logger.LogTrace(ILogger_Fields.SECURITY, "Role " + role + " removed from " + AccountName);
        }

        /// <summary> In this implementation, we have chosen to use a random token that is
        /// stored in the User object. Note that it is possible to avoid the use of
        /// server side state by using either the hash of the users's session id or
        /// an encrypted token that includes a timestamp and the user's IP address.
        /// user's IP address. A relatively short 8 character string has been chosen
        /// because this token will appear in all links and forms.
        /// </summary>        
        /// <returns> The CSRF token.
        /// </returns> 
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.ResetCsrfToken()">
        /// </seealso>
        public string ResetCsrfToken()
        {
            // user.CsrfToken = Esapi.Encryptor().hash( session.getId(),user.name );
            // user.CsrfToken = Esapi.Encryptor().encrypt( address + ":" + Esapi.Encryptor().getTimeStamp();
            csrfToken = Esapi.Randomizer().GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
            return CsrfToken;
        }

        /// <summary> 
        /// Resets the password for the user.        
        /// </summary>        
        /// <returns> 
        /// The new password for the user.
        /// </returns>        
        public string ResetPassword()
        {
            string newPassword = Esapi.Authenticator().GenerateStrongPassword();
            ChangePassword(newPassword, newPassword);
            return newPassword;
        }


        /// <summary> 
        /// Returns a token to be used as a "remember me" cookie. The cookie is not seen by the user and can be fairly long,
        /// at least 20 digits is suggested to prevent brute force attacks. See LoginWithRememberToken.        
        /// </summary>
        /// <returns> The remember token.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.ResetRememberToken()">
        /// </seealso>
        public string ResetRememberToken()
        {
            rememberToken = Esapi.Randomizer().GetRandomString(20, Encoder.CHAR_ALPHANUMERICS);
            logger.LogTrace(ILogger_Fields.SECURITY, "New remember token generated for: " + AccountName);
            return rememberToken;
        }

        /// <summary> 
        /// Returns a string for serializing the user data.        
        /// </summary>
        /// <returns>
        /// The user data in a string format.
        /// </returns>
        protected internal string Save()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(accountName);
            sb.Append(" | ");
            sb.Append(GetHashedPassword());
            sb.Append(" | ");
            sb.Append(Dump(Roles));
            sb.Append(" | ");
            sb.Append(Locked ? "locked" : "unlocked");
            sb.Append(" | ");
            sb.Append(Enabled ? "enabled" : "disabled");
            sb.Append(" | ");
            sb.Append(RememberToken);
            sb.Append(" | ");
            sb.Append(Dump(oldPasswordHashes));
            sb.Append(" | ");
            sb.Append(GetLastHostAddress());
            sb.Append(" | ");            
            sb.Append(GetLastPasswordChangeTime().Ticks);
            sb.Append(" | ");
            sb.Append(GetLastLoginTime().Ticks);
            sb.Append(" | ");            
            sb.Append(GetLastFailedLoginTime().Ticks);
            sb.Append(" | ");            
            sb.Append(ExpirationTime.Ticks);
            sb.Append(" | ");
            sb.Append(FailedLoginCount);
            return sb.ToString();
        }


        /// <summary>
        /// Returns the users hashed password.
        /// </summary>
        /// <returns>The users hashed password.</returns>        
        public string GetHashedPassword()
        {
            return hashedPassword;
        }

        /// <summary> 
        /// Sets the hashed password.
        /// </summary>
        /// <param name="hash">
        /// The hash to set the users hashed password value to.
        /// </param>
        internal void SetHashedPassword(string hash)
        {
            oldPasswordHashes.Add(hashedPassword);
            if (oldPasswordHashes.Count > Esapi.SecurityConfiguration().MaxOldPasswordHashes)
                oldPasswordHashes.RemoveAt(0);
            hashedPassword = hash;
            logger.LogCritical(ILogger_Fields.SECURITY, "New hashed password stored for " + AccountName);
        }

        /// <summary> 
        /// Sets the last failed login time for the user.       
        /// </summary>
        /// <param name="lastFailedLoginTime">
        /// The DateTime value to set.
        /// </param>
        protected internal void SetLastFailedLoginTime(DateTime lastFailedLoginTime)
        {
            this.lastFailedLoginTime = lastFailedLoginTime;
            logger.LogCritical(ILogger_Fields.SECURITY, "Set last failed login time to " + lastFailedLoginTime.ToString("r") + " for " + AccountName);
        }


        // FIXME: is this needed?
        /// <summary> 
        /// Sets the last remote host address used by this User.
        /// </summary>
        /// <param name="remoteHost">
        /// The remote host to set the last host address value.
        /// </param>
        protected internal void SetLastHostAddress(string remoteHost)
        {
            if (!lastHostAddress.Equals(remoteHost))
            {
                new AuthenticationHostException("Host change", "User session just jumped from " + lastHostAddress + " to " + remoteHost);
                lastHostAddress = remoteHost;
            }
        }

        /// <summary> 
        /// Sets the last login time.
        /// </summary>
        /// <param name="lastLoginTime">
        /// The value to set the lastLoginTime.
        /// </param>        
        protected internal void SetLastLoginTime(DateTime lastLoginTime)
        {
            this.lastLoginTime = lastLoginTime;            
            logger.LogCritical(ILogger_Fields.SECURITY, "Set last successful login time to " + lastLoginTime.ToString("r") + " for " + AccountName);
        }

        /// <summary> 
        /// Sets the last password change time.        
        /// </summary>
        /// <param name="lastPasswordChangeTime">
        /// The value to set the lastPasswordChangeTime.
        /// </param>        
        protected internal void SetLastPasswordChangeTime(DateTime lastPasswordChangeTime)
        {
            this.lastPasswordChangeTime = lastPasswordChangeTime;            
            logger.LogCritical(ILogger_Fields.SECURITY, "Set last password change time to " + lastPasswordChangeTime.ToString("r") + " for " + AccountName);
        }

        /// <summary>
        /// Returns the user account name and label.
        /// </summary>
        /// <returns>A label and the user account name.</returns>
        public override string ToString()
        {
            return "USER:" + accountName;
        }

        /// <summary> Unlocks the users account.</summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.Unlock()">
        /// </seealso>
        public void Unlock()
        {
            this.locked = false;
            logger.LogSpecial("Account unlocked: " + AccountName, null);
        }

        //FIXME:Enhance - think about having a second "transaction" password for each user


        /// <summary>
        /// Verifies the password is correct.
        /// </summary>
        /// <param name="password">The password to verify.</param>
        /// <returns>true, if the password is correct.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.VerifyPassword(string)">
        /// </seealso>
        public bool VerifyPassword(string password)
        {
            string hash = Esapi.Authenticator().HashPassword(password, accountName);
            if (hash.Equals(hashedPassword))
            {                                
                SetLastLoginTime(DateTime.Now);
                failedLoginCount = 0;
                logger.LogCritical(ILogger_Fields.SECURITY, "Password verified for " + AccountName);
                return true;
            }
            logger.LogCritical(ILogger_Fields.SECURITY, "Password verification failed for " + AccountName);                        
            SetLastFailedLoginTime(DateTime.Now);
            IncrementFailedLoginCount();
            if (FailedLoginCount >= Esapi.SecurityConfiguration().AllowedLoginAttempts)
            {
                Lock();
            }
            return false;
        }

        /// <summary>
        /// Set the is first request value
        /// </summary>
        /// <param name="b">Value to set the isFirstRequest.</param>
        protected internal void SetFirstRequest(bool b)
        {
            isFirstRequest = b;
        }

        /// <summary>
        /// Returns whether or not this is the first request.
        /// </summary>
        /// <returns>true, if this is the first request.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IUser.IsFirstRequest()">
        /// </seealso>
        public bool IsFirstRequest()
        {
            return isFirstRequest;
        }
        
        // FIXME: AAA this is a strange place for the event class to live.  Move to somewhere more appropriate.
        private class Event
        {
            public string key;
            public ArrayList times = new ArrayList();
            public long count = 0;
            public Event(string key)
            {
                this.key = key;
            }
            public void Increment(int count, long interval)
            {
                DateTime now = DateTime.Now;
                times.Insert(0, now);
                while (times.Count > count)
                    times.RemoveAt(times.Count - 1);
                if (times.Count == count)
                {
                    DateTime past = (DateTime)times[count - 1];                    
                    long plong = past.Ticks;                    
                    long nlong = now.Ticks;
                    if (nlong - plong < interval * 1000)
                    {
                        // FIXME: ENHANCE move all this event stuff inside IntrusionDetector?
                        throw new IntrusionException();
                    }
                }
            }
        }

        /// <summary>
        /// The static constructor
        /// </summary>
        static User()
        {
            logger = Logger.GetLogger("Esapi", "User");
        }
    }
}
