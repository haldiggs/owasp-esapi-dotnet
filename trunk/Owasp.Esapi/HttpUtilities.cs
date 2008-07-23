/// <summary> OWASP Enterprise Security API .NET (Esapi.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (Esapi) project. For details, please see
/// http://www.owasp.org/esapi.
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
using System.IO;
using HttpInterfaces;
using Owasp.Esapi.Interfaces;
using System.Web;
using System.Web.SessionState;
using System.Collections;
using Owasp.Esapi.Errors;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.UI.HtmlControls;

namespace Owasp.Esapi
{

    ///     
    /// <summary> Reference implementation of the IHttpUtilities interface.
	/// 
	/// To simplify the interface, this class uses the current request and response that
	/// are tracked by ThreadLocal variables in the Authenticator. This means that you
	/// must have set Esapi.Authenticator().Context before
	/// calling these methods. This is done automatically by the Authenticator.Login() method.
	/// 
	/// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
	/// <seealso cref="Owasp.Esapi.HttpUtilities">
	/// </seealso>
    public class HttpUtilities : IHttpUtilities
    {
		private void  InitBlock()
		{
			maxBytes = Esapi.SecurityConfiguration().AllowedFileUploadSize;
		}
		/// <summary> Returns true if the request was transmitted over an SSL enabled
		/// connection. This implementation ignores the built-in IsSecure() method
		/// and uses the URL to determine if the request was transmitted over SSL.
		/// </summary>
		public bool SecureChannel
		{
			get
			{
				IHttpRequest request = ((Authenticator) Esapi.Authenticator()).CurrentRequest;
				return (request.Url.ToString()[4] == 's');
			}
			
		}
		
		/// <summary>The logger. </summary>
		private static readonly Logger logger;
		
		/// <summary>The max bytes. </summary>		
		internal int maxBytes;
		
        /// <summary>
        /// Constructor for HttpUtilities. Need initialization method to set the maxBytes value from the security configuration.
        /// </summary>
		public HttpUtilities()
		{
			InitBlock();
		}
		
		// FIXME: Enhance - consider adding AddQueryChecksum(String href) that would just verify that none of the parameters in the querystring have changed.  Could do the same for forms.
		// FIXME: Enhance - also VerifyQueryChecksum()
		
		
		
		// FIXME: need to make this easier to add to forms.
        /// <summary> Adds the current user's CSRF token (see User.GetCSRFToken()) to the URL for purposes of preventing CSRF attacks.
        /// This method should be used on all URLs to be put into all links and forms the application generates.        
        /// </summary>
        /// <param name="href"> The URL to append the CSRF token to.
        /// </param>
        /// <returns> The updated href with the CSRF token parameter.
        /// </returns>
		/// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.AddCsrfToken(string)">
		/// </seealso>
		public string AddCsrfToken(string href)
		{
			User user = (User) Esapi.Authenticator().GetCurrentUser();
			
			// FIXME: AAA getCurrentUser should never return null
			if (user.Anonymous || user == null)
			{
				return href;
			}
			
			if ((href.IndexOf('?') != - 1) || (href.IndexOf('&') != - 1))
			{
				return href + "&" + user.CsrfToken;
			}
			else
			{
				return href + "?" + user.CsrfToken;
			}
		}
		
		
		/// <summary> Adds a cookie to the HttpResponse that uses Secure and HttpOnly
		/// flags.
		/// </summary>
        /// <param name="name">The name of the cookie.
        /// </param>
        /// <param name="cookieValue">The value of the cookie.
        /// </param>
        /// <param name="domain">The domain for the cookie.
        /// </param>
        /// <param name="path">The path for the cookie.
        /// </param>
        /// <param name="maxAge">The max age of the cookie.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.SafeAddCookie(string, string, int, string, string)">
		/// </seealso>
		public  void  SafeAddCookie(string name, string cookieValue, int maxAge, string domain, string path)
		{
            // TODO - Potentially try to work with HttpCookies
            IHttpResponse response = ((Authenticator)Esapi.Authenticator()).CurrentResponse;
            // FIXME: Enhance - this most likely occurs if someone calls setNoCacheHeaders() before login
            if (response == null) throw new NullReferenceException("Can't set response header until current response is set, typically via login");

		    // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
			// domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
			// FIXME: AAA test if setting a separate set-cookie header for each cookie works!
            
		    string header = name + "=" + cookieValue;
			if (maxAge != - 1)
				header += ("; Max-Age=" + maxAge);
			if (domain != null)
				header += ("; Domain=" + domain);
			if (path != null)
				header += ("; Path=" + path);
			header += "; Secure; HttpOnly";            
			response.AppendHeader("Set-Cookie", header);
		}
		


        /// <summary>
        /// Adds a header to an HttpResponse after checking for special
        /// characters (such as CRLF injection) that could enable attacks like
        /// response splitting and other header-based attacks that nobody has thought
        /// of yet.
        /// </summary>
        /// <param name="name">The name of the header.
        /// </param>
        /// <param name="val">The value of the cookie.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.SafeAddHeader(string, string)">
        /// </seealso>
        public  void  SafeAddHeader(string name, string val)
		{
			IHttpResponse response = ((Authenticator) Esapi.Authenticator()).CurrentResponse;
            // FIXME: Enhance - this most likely occurs if someone calls setNoCacheHeaders() before login
            if (response == null) throw new NullReferenceException("Can't set response header until current response is set, typically via login");

            // FIXME: AAA consider using the regex for header names and header values here
			Regex headerName = ((SecurityConfiguration) Esapi.SecurityConfiguration()).GetValidationPattern("HTTPHeaderName");
			if (!headerName.IsMatch(name))
			{
				throw new ValidationException("Invalid header", "Attempt to set a header name that violates the global rule in Esapi.properties: " + name);
			}
			Regex headerValue = ((SecurityConfiguration) Esapi.SecurityConfiguration()).GetValidationPattern("HTTPHeaderValue");
			if (!headerValue.IsMatch(val))
			{
				throw new ValidationException("Invalid header", "Attempt to set a header value that violates the global rule in Esapi.properties: " + headerValue);
			}
			response.AppendHeader(name, val);
		}

        /// <summary>
        /// Sets a header to an HttpResponse after checking for special
        /// characters (such as CRLF injection) that could enable attacks like
        /// response splitting and other header-based attacks that nobody has thought
        /// of yet.
        /// </summary>
        /// <param name="name">The name of the header.
        /// </param>
        /// <param name="val">The value of the cookie.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.SafeSetHeader(string, string)">
        /// </seealso>
        public void SafeSetHeader(String name, String value) 
        {
            IHttpResponse response = ((Authenticator)Esapi.Authenticator()).CurrentResponse;
            // FIXME: Enhance - this most likely occurs if someone calls setNoCacheHeaders() before login
            if (response == null) throw new NullReferenceException("Can't set response header until current response is set, typically via login");

            Regex headerName = ((SecurityConfiguration)Esapi.SecurityConfiguration()).GetValidationPattern("HTTPHeaderName");
            if (!headerName.IsMatch(name))
            {
                throw new ValidationException("Invalid header", "Attempt to set a header name that violates the global rule in Esapi.properties: " + name);
            } 
                        
            Regex headerValue = ((SecurityConfiguration)Esapi.SecurityConfiguration()).GetValidationPattern("HTTPHeaderValue");
            if (!headerValue.IsMatch(value))
            {
                throw new ValidationException("Invalid header", "Attempt to set a header value that violates the global rule in Esapi.properties: " + headerValue);
            }
		    response.Headers[name] = value;
	}
        
        
		
		//FIXME: AAA add these to the interface
		/// <summary> Return exactly what was sent to prevent URL rewriting. URL rewriting is intended to be a session management
		/// scheme that doesn't require cookies, but exposes the sessionid in many places, including the URL bar,
		/// favorites, HTML files in cache, logs, and cut-and-paste links. For these reasons, session rewriting is
		/// more dangerous than the evil cookies it was intended to replace.
		/// 
		/// </summary>
		/// <param name="url">The URL to encode.
		/// </param>
		/// <returns>
        /// The safely encoded URL.
		/// </returns>
		public  string SafeEncodeURL(string url)
		{
			return url;
		}
		
		/// <summary> Return exactly what was sent to prevent URL rewriting. URL rewriting is intended to be a session management
		/// scheme that doesn't require cookies, but exposes the sessionid in many places, including the URL bar,
		/// favorites, HTML files in cache, logs, and cut-and-paste links. For these reasons, session rewriting is
		/// more dangerous than the evil cookies it was intended to replace.
		/// 
		/// </summary>
		/// <param name="url">The URL to encode.
		/// </param>
		/// <returns>
        /// The safely encoded URL
		/// </returns>
		public string SafeEncodeRedirectURL(string url)
		{
			return url;
		}



        /// <summary> Invalidate the old session after copying all of its contents to a newly created session with a new session id.
        /// Note that this is different from logging out and creating a new session identifier that does not contain the
        /// existing session contents. Care should be taken to use this only when the existing session does not contain
        /// hazardous contents.
        /// 
        /// </summary>
        /// <returns> The invaldiated session.
        /// </returns>   
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.ChangeSessionIdentifier()">
        /// </seealso>
		public IHttpSession ChangeSessionIdentifier()
		{
			IHttpRequest request = ((Authenticator) Esapi.Authenticator()).CurrentRequest;
            IHttpResponse response = ((Authenticator) Esapi.Authenticator()).CurrentResponse;
            IHttpSession session = ((Authenticator)Esapi.Authenticator()).CurrentSession;            
            IDictionary temp = new Hashtable();
			
			
			// make a copy of the session content
			IEnumerator e = session.GetEnumerator();			
			while (e != null && e.MoveNext())
			{				
				string name = (string) e.Current;
				object val = session[name];
				temp[name] = val;
			}
			
            // invalidate the old session and create a new one

            // This hack comes from here: http://support.microsoft.com/?kbid=899918
			session.Abandon();
            response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));
			
			// copy back the session content			
			IEnumerator i = new ArrayList(temp).GetEnumerator();			
			while (i.MoveNext())
			{				
				DictionaryEntry entry = (DictionaryEntry) i.Current;
				session.Add((string) entry.Key, entry.Value);
			}
			return session;
		}
		
		
		
		// FIXME: ENHANCE - add configuration for entry pages that don't require a token 
        /// <summary> Checks the CSRF token in the URL (see User.GetCSRFToken()) against the user's CSRF token and throws
        /// an exception if they don't match.
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.VerifyCsrfToken()">
        /// </seealso>
		public void  VerifyCsrfToken()
		{
			IHttpRequest request = ((Authenticator) Esapi.Authenticator()).CurrentRequest;
			User user = (User) Esapi.Authenticator().GetCurrentUser();
			// if this is the first request after logging in, let them pass
			if (user.IsFirstRequest())
				return ;
						
			if (request[user.CsrfToken] == null)
			{
                throw new IntrusionException("Authentication failed", "Possibly forged HTTP request without proper CSRF token detected");
			}
		}
		
        /// <summary>
        /// Decrypt the string from a hidden field.
        /// </summary>
        /// <param name="encrypted">The encrypted string (ciphertext).</param>
        /// <returns>The decrypted string (cleartext).</returns>
		public string DecryptHiddenField(string encrypted)
		{
			try
			{
				return Esapi.Encryptor().Decrypt(encrypted);
			}
			catch (EncryptionException e)
			{
				throw new IntrusionException("Invalid request", "Tampering detected. Hidden field data did not decrypt properly.", e);
			}
		}


        /// <summary>
        /// Decrypt the query string.
        /// </summary>
        /// <param name="encrypted">The encrypted string (ciphertext).</param>
        /// <returns>The decrypted name-value collection (cleartext).</returns>
		public IDictionary DecryptQueryString(string encrypted)
		{
			// FIXME: AAA needs test cases
			string cleartext = Esapi.Encryptor().Decrypt(encrypted);
			return QueryToMap(cleartext);
		}

        /// <summary>
        /// Decrypt the cookies.
        /// </summary>
        /// <returns>The decrypted name-value collection (cleartext).</returns>
		public IDictionary DecryptStateFromCookie()
		{
			IHttpRequest request = ((Authenticator) Esapi.Authenticator()).CurrentRequest;
			HttpCookieCollection cookies = request.Cookies;
			string encrypted = cookies["state"].Value;
			string cleartext = Esapi.Encryptor().Decrypt(encrypted);
			
			return QueryToMap(cleartext);
		}

        /// <summary>
        /// Encrypt the string from a hidden field.
        /// </summary>
        /// <param name="fieldValue">The decrypted string (cleartext).</param>
        /// <returns>The encrypted string (ciphertext).</returns>
		public string EncryptHiddenField(string fieldValue)
		{
			return Esapi.Encryptor().Encrypt(fieldValue);
		}

        /// <summary>
        /// Encrypt the query string.
        /// </summary>
        /// <param name="query">The decrypted string (cleartext).</param>
        /// <returns>The encrypted string (ciphertext).</returns>
		public string EncryptQueryString(string query)
		{
			return Esapi.Encryptor().Encrypt(query);
		}

        /// <summary>
        /// Encrypt values into a cookie.
        /// </summary>
        /// <param name="cleartext">The decrypted string (cleartext).</param>
        /// <returns>The encrypted string (ciphertext).</returns>
		public void EncryptStateInCookie(IDictionary cleartext)
		{
			StringBuilder sb = new StringBuilder();			
			IEnumerator i = new ArrayList(cleartext).GetEnumerator();
            bool first = true;
			while (i.MoveNext())
			{
				try
				{		
				    if (!first)
				    {
                        sb.Append("&");
				    } else
				    {
				        first = false;
				    }
				    DictionaryEntry entry = (DictionaryEntry) i.Current;					
					string name = Esapi.Encoder().EncodeForUrl(entry.Key.ToString());					
					string cookieValue = Esapi.Encoder().EncodeForUrl(entry.Value.ToString());
					sb.Append(name + "=" + cookieValue);					
					
				}
				catch (EncodingException e)
				{
					// continue
				}
			}
			// FIXME: AAA - add a check to see if cookie length will exceed 2K limit
			string encrypted = Esapi.Encryptor().Encrypt(sb.ToString());
			this.SafeAddCookie("state", encrypted, - 1, null, null);
		}
		

        // FIXME: No progress indicator.
		/// <summary> Uses the .NET HttpFileCollection object. to parse the multipart HTTP request
		/// and extract any files therein. 
		/// </summary>
        /// <param name="tempDir">
        /// The temporary directory where the file is written.
        /// </param>
        /// <param name="finalDir">
        /// The final directory where the file will be written.
        /// </param>
		/// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.GetSafeFileUploads(FileInfo, FileInfo)">
		/// </seealso>        
        public IList GetSafeFileUploads(DirectoryInfo tempDir, DirectoryInfo finalDir)
        {
            ArrayList newFiles = new ArrayList();
            try
            {
                if (!tempDir.Exists)
                {
                    tempDir.Create();
                }
                if (!finalDir.Exists)
                {
                    finalDir.Create();
                }
                IHttpFileCollection fileCollection = ((Authenticator)Esapi.Authenticator()).CurrentRequest.Files;
                if (fileCollection.AllKeys.Length == 0)
                {
                    throw new ValidationUploadException("Upload failed", "Not a multipart request");
                }

                // No progress meter yet
                foreach (string key in fileCollection.AllKeys)
                {
                    IHttpPostedFile file = fileCollection[key];
                    if (file.FileName != null && !file.FileName.Equals(""))
                    {
                        String[] fparts = Regex.Split(file.FileName, "[\\/\\\\]");
                        String filename = fparts[fparts.Length - 1];
                        if (!Esapi.Validator().IsValidFileName("upload", filename, false))
                        {
                            string extensions = "";
                            foreach (string ext in Esapi.SecurityConfiguration().AllowedFileExtensions)
                            {
                                extensions += ext + "|";
                            }
                            throw new ValidationUploadException("Upload only simple filenames with the following extensions "  + extensions,"Invalid filename for upload");
                        }
                        logger.LogCritical(ILogger_Fields.SECURITY, "File upload requested: " + filename);
                        FileInfo f = new FileInfo(finalDir.ToString() +  "\\" + filename);
                        if (f.Exists)
                        {
                            String[] parts = Regex.Split(filename, "\\./");
                            String extension = "";
                            if (parts.Length > 1)
                            {
                                extension = parts[parts.Length - 1];
                            }
                            String filenm = filename.Substring(0, filename.Length - extension.Length);

                            // Not sure if this is good enough solution for file overwrites
                            f = new FileInfo(finalDir + "\\" + filenm + Guid.NewGuid() + "." + extension);
                        }
                        file.SaveAs(f.FullName);
                        newFiles.Add(f);
                        logger.LogCritical(ILogger_Fields.SECURITY, "File successfully uploaded: " + f);                        
                    }
                }
                logger.LogCritical(ILogger_Fields.SECURITY, "File successfully uploaded: ");
                //session.Add("progress", System.Convert.ToString(0));
            }

            catch (Exception ex)
            {
                if (ex is ValidationUploadException)
                    throw (ValidationException)ex;
                throw new ValidationUploadException("Upload failure", "Problem during upload");
            }
            return newFiles;
        }

        /// <summary> Kill all cookies received in the last request from the browser. Note that new cookies set by the application in
        /// this response may not be killed by this method.        
        /// </summary>
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.KillAllCookies()">
        /// </seealso>
		public  void  KillAllCookies()
		{
			IHttpRequest request = ((Authenticator) Esapi.Authenticator()).CurrentRequest;
            HttpCookieCollection cookies = request.Cookies;
			if (cookies != null)
			{
				foreach (string cookieName in cookies)
				{					
					KillCookie(cookieName);
				}
			}
		}

        /// <summary> Kills the specified cookie by setting a new cookie that expires immediately.
        /// </summary>
        /// <param name="name">The name of the cookie to kill.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.KillCookie(string)">
        /// </seealso>
		public  void  KillCookie(string name)
		{
			IHttpRequest request = ((Authenticator) Esapi.Authenticator()).CurrentRequest;
			IHttpResponse response = ((Authenticator) Esapi.Authenticator()).CurrentResponse;
			HttpCookieCollection cookies = request.Cookies;
			if (cookies != null)
			{
				foreach (string cookieName in cookies)
				{					
					if (cookieName.Equals(name))
					{
						string path = request.ApplicationPath;
						string header = name + "=deleted; Max-Age=0; Path=" + path;
						response.AppendHeader("Set-Cookie", header);
					}
				}
			}
		}
		
        /// <summary>
        /// This method extracts the name/value pairs from a query string.
        /// </summary>
        /// <param name="query">The query to parse</param>
        /// <returns>The parsed name/value pairs</returns>
		private IDictionary QueryToMap(string query)
		{			
			SortedList map = new SortedList();
			string[] parts = Regex.Split(query, "&");
			for (int j = 0; j < parts.Length; j++)
			{
				try
				{
					string[] nvpair = Regex.Split(parts[j], "=");
					string name = Esapi.Encoder().DecodeFromUrl(nvpair[0]);
					string val = Esapi.Encoder().DecodeFromUrl(nvpair[1]);
					map[name] = val;
				}
				catch (EncodingException e)
				{
					// skip and continue
				}
			}
			return map;
		}
		
        /// <summary>
        ///  This method forwards the request safely.
        /// </summary>
        /// <param name="context">The context for the forward.</param>
        /// <param name="location">The location to forward the request.</param>        
		public  void  SafeSendForward(string context, string location)
		{
			// FIXME: should this be configurable?  What is a good forward policy?
			// I think not allowing forwards to public URLs is good, as it bypasses many access controls
			
			IHttpRequest request = ((Authenticator) Esapi.Authenticator()).CurrentRequest;
			IHttpResponse response = ((Authenticator) Esapi.Authenticator()).CurrentResponse;
            // FIXME: Implement.
            throw new NotImplementedException();
		}

        /// <summary> This method generates a redirect response that can only be used to redirect the browser to safe locations.
        /// Importantly, redirect requests can be modified by attackers, so do not rely information contained within redirect
        /// requests, and do not include sensitive infomration in a redirect.
        /// </summary>
        /// <param name="context">
        /// The context for the redirection.
        /// </param>
        /// <param name="location">The URL to redirect to.
        /// </param>
        /// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.SafeSendRedirect(string, string)">
        /// </seealso>
		public void SafeSendRedirect(string context, string location)
		{
			IHttpResponse response = ((Authenticator) Esapi.Authenticator()).CurrentResponse;
            // FIXME: Enhance - this most likely occurs if someone calls setNoCacheHeaders() before login
            if (response == null) throw new NullReferenceException("Can't set response header until current response is set, typically via login");
            if (!Esapi.Validator().IsValidRedirectLocation(context, location, false))
			{
				throw new ValidationException("Redirect failed", "Bad redirect location: " + location);
			}			
			response.Redirect(location);
		}
		
		/// <summary> Set the character encoding on every HttpResponse in order to limit
		/// the ways in which the input data can be represented. This prevents
		/// malicious users from using encoding and multi-byte escape sequences to
		/// bypass input validation routines. The default is text/html; charset=UTF-8
		/// character encoding, which is the default in early versions of HTML and
		/// HTTP. See RFC 2047 (http://ds.internic.net/rfc/rfc2045.txt) for more
		/// information about character encoding and MIME.
		/// </summary>        
		/// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.SafeSetContentType()">
		/// </seealso>
		public  void  SafeSetContentType()
		{
			IHttpResponse response = ((Authenticator) Esapi.Authenticator()).CurrentResponse;
            // FIXME: Enhance - this most likely occurs if someone calls setNoCacheHeaders() before login
            if (response == null) throw new NullReferenceException("Can't set response header until current response is set, typically via login");
			response.ContentType = ((SecurityConfiguration) Esapi.SecurityConfiguration()).ResponseContentType;
		}
		
		/// <summary> Set headers to protect sensitive information against being cached in the
		/// browser.
		/// </summary>
		/// <seealso cref="Owasp.Esapi.Interfaces.IHttpUtilities.SetNoCacheHeaders()">
		/// </seealso>
		public  void  SetNoCacheHeaders()
		{
			IHttpResponse response = ((Authenticator) Esapi.Authenticator()).CurrentResponse;
            if (response == null) throw new NullReferenceException("Can't set response header until current response is set, typically via login");
		
			// HTTP 1.1
			response.AppendHeader("Cache-Control", "no-store");
			response.AppendHeader("Cache-Control", "no-cache");
			response.AppendHeader("Cache-Control", "must-revalidate");
			
			// HTTP 1.0
			response.AppendHeader("Pragma", "no-cache");
			response.AppendHeader("Expires", DateTime.MinValue.ToString("r"));
		}
        

        /// <summary>
        /// Static constructor.
        /// </summary>
		static HttpUtilities()
		{
			logger = Logger.GetLogger("Esapi", "HttpUtilities");
		}
    }
}
