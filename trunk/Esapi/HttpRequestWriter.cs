using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Web;

namespace Owasp.Esapi
{
    /// <summary>
    /// HTTP request writer
    /// </summary>
    internal class HttpRequestWriter : HttpDataWriter
    {
        internal HttpRequestWriter(TextWriter output)
            : base(output)
        {
        }

        /// <summary>
        /// Write HTTP request
        /// </summary>
        /// <param name="request"></param>
        /// <param name="user"></param>
        /// <param name="obfuscatedParams"></param>
        /// <param name="verbose"></param>
        internal void Write(HttpRequest request, IPrincipal user, ICollection<string> obfuscatedParams, bool verbose)
        {
            if (request == null) {
                throw new ArgumentNullException("user");
            }

            IPrincipal userPrincipal = (user == null ? Esapi.SecurityConfiguration.CurrentUser : user);

            //
            WriteHeader("HttpRequestData");

            // User
            WriteSection("User");
            WriteValue("Identity", (userPrincipal != null ? userPrincipal.Identity.Name : "<not set>"));
            WriteValue("HostName", request.UserHostName);
            WriteValue("HostAddress", request.UserHostAddress);
            WriteValue("IsAuthenticated", request.IsAuthenticated.ToString());

            // Request
            WriteSection("Request");
            WriteValue("RawUrl", request.RawUrl);
            WriteValue("HttpMethod", request.HttpMethod);
            WriteValue("IsSecure", request.IsSecureConnection.ToString());

            // Cookies
            WriteSection("Cookies");
            foreach (HttpCookie cookie in request.Cookies) {
                WriteValue(cookie.Name, cookie.ToString());
            }

            // Headers
            WriteSection("Headers");
            WriteValues(request.Headers);

            // Form 
            WriteSection("Form");
            WriteObfuscatedValues(request.Form, obfuscatedParams);

            // Params
            WriteSection("Params");
            WriteObfuscatedValues(request.Params, obfuscatedParams);

            if (verbose) {
                // Server variables
                WriteSection("ServerVariables");
                WriteObfuscatedValues(request.ServerVariables, obfuscatedParams);
            }

            // Done
            WriteFooter();
        }
    }
}
