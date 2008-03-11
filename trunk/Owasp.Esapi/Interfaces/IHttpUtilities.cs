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
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone[/a]
/// </author>
/// <created>  2008 </created>

using System;
using System.IO;
using HttpInterfaces;

namespace Owasp.Esapi.Interfaces
{

    /// <summary> The IHTTPUtilities interface is a collection of methods that provide additional security related to HTTP requests,
    /// responses, sessions, cookies, headers, and logging.
    /// [P]
    /// [img src="doc-files/HTTPUtilities.jpg" height="600"]
    /// [P]
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    public interface IHttpUtilities
    {
        /// <summary> Returns true if the request and response are using an SSL-enabled connection. This check should be made on
        /// every request from the login page through the logout confirmation page. Essentially, any page that uses the
        /// Authenticator.Login() call should call this. Implementers should consider calling this method directly in
        /// their Authenticator.Login() method. If this method returns true for a page that requires SSL, there must be a
        /// misconfiguration, an AuthenticationException is warranted. 
        /// </summary>
        bool SecureChannel
        {
            get;

        }

        /// <summary> Adds the current user's CSRF token (see User.GetCSRFToken()) to the URL for purposes of preventing CSRF attacks.
        /// This method should be used on all URLs to be put into all links and forms the application generates.        
        /// </summary>
        /// <param name="href"> The URL to append the CSRF token to.
        /// </param>
        /// <returns> The updated href with the CSRF token parameter.
        /// </returns>
        string AddCsrfToken(string href);


        /// <summary> Adds a cookie to the specified HttpServletResponse and adds the Http-Only flag.
        /// 
        /// </summary>
        /// <param name="name">The name of the cookie.
        /// </param>
        /// <param name="value">The value of the cookie.
        /// </param>
        /// <param name="domain">The domain for the cookie.
        /// </param>
        /// <param name="path">The path for the cookie.
        /// </param>
        /// <param name="maxAge">The max age of the cookie.
        /// </param>
        void SafeAddCookie(string name, string value, int maxAge, string domain, string path);

        /// <summary> Adds a header to an HttpResponse after checking for special characters (such as CRLF injection) that could enable 
        /// attacks like response splitting and other header-based attacks that nobody has thought of yet. 
        /// 
        /// </summary>
        /// <param name="name">The name of the header.
        /// </param>
        /// <param name="value">The value of the cookie.
        /// </param>
        void SafeAddHeader(string name, string value);

        /// <summary> Invalidate the old session after copying all of its contents to a newly created session with a new session id.
        /// Note that this is different from logging out and creating a new session identifier that does not contain the
        /// existing session contents. Care should be taken to use this only when the existing session does not contain
        /// hazardous contents.
        /// 
        /// </summary>
        /// <returns> The invaldiated session.
        /// </returns>        
        IHttpSession ChangeSessionIdentifier();

        /// <summary> Checks the CSRF token in the URL (see User.GetCSRFToken()) against the user's CSRF token and throws
        /// an exception if they don't match.
        /// </summary>
        void VerifyCsrfToken();

        /// <summary> Extract uploaded files from a multipart HTTP requests. Implementations must check the content to ensure that it
        /// is safe before making a permanent copy on the local filesystem. Checks should include length and content checks,
        /// possibly virus checking, and path and name checks. Refer to the file checking methods in IValidator for more
        /// information.
        /// </summary>
        /// <param name="tempDir">The temp directory to write to.
        /// </param>
        /// <param name="finalDir">The final directory to write to.
        /// </param>
        /// <throws>  ValidationException the validation exception </throws>
        void GetSafeFileUploads(FileInfo tempDir, FileInfo finalDir);

        /// <summary> Kill all cookies received in the last request from the browser. Note that new cookies set by the application in
        /// this response may not be killed by this method.        
        /// </summary>
        void KillAllCookies();

        /// <summary> Kills the specified cookie by setting a new cookie that expires immediately.
        /// </summary>
        /// <param name="name">The name of the cookie to kill.
        /// </param>
        void KillCookie(string name);


        /// <summary> This method generates a redirect response that can only be used to redirect the browser to safe locations.
        /// Importantly, redirect requests can be modified by attackers, so do not rely information contained within redirect
        /// requests, and do not include sensitive infomration in a redirect.
        /// </summary>
        /// <param name="context">The context for validation.
        /// </param>
        /// <param name="location">The URL to redirect to.
        /// </param>
        void SafeSendRedirect(string context, string location);



        /// <summary> Sets the content type on each HTTP response, to help protect against cross-site scripting attacks and other types
        /// of injection into HTML documents.
        /// </summary>
        void SafeSetContentType();


        /// <summary> Set headers to protect sensitive information against being cached in the browser. Developers should make this
        /// call for any HTTP responses that contain any sensitive data that should not be cached within the browser or any
        /// intermediate proxies or caches. Implementations should set headers for the expected browsers. The safest approach
        /// is to set all relevant headers to their most restrictive setting. These include:
        /// 
        /// [PRE]
        /// 
        /// Cache-Control: no-store[BR]
        /// Cache-Control: no-cache[BR]
        /// Cache-Control: must-revalidate[BR]
        /// Expires: -1[BR]
        /// 
        /// [/PRE]
        /// 
        /// Note that the header "pragma: no-cache" is only useful in HTTP requests, not HTTP responses. So even though there
        /// are many articles recommending the use of this header, it is not helpful for preventing browser caching. For more
        /// information, please refer to the relevant standards:
        /// [UL]
        /// [LI][a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html"]HTTP/1.1 Cache-Control "no-cache"[/a]
        /// [LI][a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1"]HTTP/1.1 Cache-Control "no-store"[/a]
        /// [LI][a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2"]HTTP/1.0 Pragma "no-cache"[/a]
        /// [LI][a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.32"]HTTP/1.0 Expires[/a]
        /// [LI][a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21"]IE6 Caching Issues[/a]
        /// [LI][a href="http://support.microsoft.com/kb/937479"]Firefox browser.cache.disk_cache_ssl[/a]
        /// [LI][a href="http://www.mozilla.org/quality/networking/docs/netprefs.html"]Mozilla[/a]
        /// [/UL]
        /// 
        /// </summary>
        void SetNoCacheHeaders();

    }
}
