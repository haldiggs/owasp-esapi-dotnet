using System;

namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// </summary>    
    public interface IAccessController
    {
        bool IsAuthorized(object action, object resource);
        bool IsAuthorized(object subject, object action, object resource);
        void AddRule(object subject, object action, object resource);
        void RemoveRule(object subject, object action, object resource);
    }
}
