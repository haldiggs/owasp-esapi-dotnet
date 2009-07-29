using System.Web;
using System.Web.SessionState;
using System.Web.UI;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    class HttpUtilities: IHttpUtilities
    {
        public const string CSRF_TOKEN_NAME = "CsrfToken";
        #region IHttpUtilities Members


        public void AddCsrfToken()
        {
            HttpContext context = HttpContext.Current;
            ((Page)context.CurrentHandler).ViewStateUserKey = context.Session.SessionID;
        }

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

        public void VerifyCsrfToken()
        {
            string csrfToken = (string)HttpContext.Current.Session[CSRF_TOKEN_NAME];
            string receivedCsrfToken = HttpContext.Current.Request.QueryString[CSRF_TOKEN_NAME]; 
            if (receivedCsrfToken == null || !receivedCsrfToken.Equals(csrfToken)) { 
                throw new IntrusionException("Authentication failed", "Possibly forged HTTP request without proper CSRF token detected"); 
            } 
        }

        public void ChangeSessionIdentifier()
        {
            SessionIDManager manager = new SessionIDManager();
            string newSessionId = manager.CreateSessionID(HttpContext.Current);            
            bool redirected = false;
            bool IsAdded = false; 
            manager.SaveSessionID(HttpContext.Current, newSessionId, out redirected, out IsAdded);            
        }

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
