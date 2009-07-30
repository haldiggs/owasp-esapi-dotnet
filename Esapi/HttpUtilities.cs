using System.Web;
using System.Web.SessionState;
using System.Web.UI;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IHttpUtilities" />
    /// <remarks>
    /// Reference implementation for the <see cref="Owasp.Esapi.Interfaces.IHttpUtilities"/> class.
    /// </remarks>
    public class HttpUtilities: IHttpUtilities
    {
        /// <summary>
        /// The name to use for the CSRF token.
        /// </summary>
        public const string CSRF_TOKEN_NAME = "CsrfToken";
        #region IHttpUtilities Members

        /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IHttpUtilities.AddCsrfToken()" />
        public void AddCsrfToken()
        {
            HttpContext context = HttpContext.Current;
            ((Page)context.CurrentHandler).ViewStateUserKey = context.Session.SessionID;
        }

        /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IHttpUtilities.AddCsrfToken(string)" />
        public string AddCsrfToken(string href)
        {
            string csrfToken = (string) HttpContext.Current.Session[CSRF_TOKEN_NAME];
            if (csrfToken == null)
            {
                csrfToken = Esapi.Randomizer.GetRandomString(8, Encoder.CHAR_ALPHANUMERICS);
                HttpContext.Current.Session[CSRF_TOKEN_NAME] = csrfToken;
            }
            string token = CSRF_TOKEN_NAME + "=" + csrfToken;
            return href.IndexOf('?') != -1 ? href + "&" + token : href + "?" + token; 
        }

        /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IHttpUtilities.VerifyCsrfToken()" />
        public void VerifyCsrfToken()
        {
            string csrfToken = (string)HttpContext.Current.Session[CSRF_TOKEN_NAME];
            string receivedCsrfToken = HttpContext.Current.Request.QueryString[CSRF_TOKEN_NAME]; 
            if (receivedCsrfToken == null || !receivedCsrfToken.Equals(csrfToken)) { 
                throw new IntrusionException("Authentication failed", "Possibly forged HTTP request without proper CSRF token detected"); 
            } 
        }

        /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IHttpUtilities.ChangeSessionIdentifier()" />
        public void ChangeSessionIdentifier()
        {
            SessionIDManager manager = new SessionIDManager();
            string newSessionId = manager.CreateSessionID(HttpContext.Current);            
            bool redirected = false;
            bool IsAdded = false; 
            manager.SaveSessionID(HttpContext.Current, newSessionId, out redirected, out IsAdded);            
        }

        /// <inheritdoc  cref="Owasp.Esapi.Interfaces.IHttpUtilities.AddNoCacheHeaders()" />
        public void AddNoCacheHeaders()
        {
            HttpResponse response = HttpContext.Current.Response;
            // HTTP 1.1
            response.AddHeader("Cache-Control", "no-store, no-cache, must-revalidate");
            // HTTP 1.0
            response.AddHeader("Pragma","no-cache");
            response.Expires = -1;
        }

        #endregion
    }
}
