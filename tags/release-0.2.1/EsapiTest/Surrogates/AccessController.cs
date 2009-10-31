using Owasp.Esapi.Interfaces;

namespace EsapiTest.Surrogates
{
    /// <summary>
    /// Custom access controller class
    /// </summary>
    /// <remarks>Need to have an explicit one because RhinoMocks
    /// cannot create named types</remarks>
    internal class SurrogateAccessController : IAccessController
    {
        public IAccessController Impl { get; set; }
        #region IAccessController Members

        public bool IsAuthorized(object action, object resource)
        {
            return Impl.IsAuthorized(action, resource);
        }

        public bool IsAuthorized(object subject, object action, object resource)
        {
            return Impl.IsAuthorized(subject, action, resource);
        }

        public void AddRule(object subject, object action, object resource)
        {
            Impl.AddRule(subject, action, resource);
        }

        public void RemoveRule(object subject, object action, object resource)
        {
            Impl.RemoveRule(subject, action, resource);
        }

        #endregion
    }
}
