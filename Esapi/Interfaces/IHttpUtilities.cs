
namespace Owasp.Esapi.Interfaces
{
    public interface IHttpUtilities
    {
        void AddCsrfToken();       

        /// <summary>
        /// Adds a CSRF token to the URL for purposes of preventing CSRF attacks.        
        /// </summary>
        /// <param name="href">the URL to which the CSRF token will be appended</param>
        /// <returns>the updated URL with the CSRF token parameter added</returns>                       
        string AddCsrfToken(string href);

        void VerifyCsrfToken();

        void AddNoCacheHeaders();

        void ChangeSessionIdentifier();        
    }
}
