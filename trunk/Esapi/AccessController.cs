using System.Collections;
using System.Web.Security;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController"/>
    /// <remarks>
    /// This is the reference implementation of the IAccessController interface. It simply
    /// stores the access control rules in nested Hashtables.
    /// </remarks>
    public class AccessController : IAccessController
    {
        private Hashtable resourceToSubjectsMap = new Hashtable();

        /// <summary>The logger.</summary>
        private static readonly ILogger logger;
        
        /// <summary> 
        /// Default constructor.        
        /// </summary>        
        public AccessController()
        {

        }
        
        /// <summary>
        /// Static constructor.
        /// </summary>
        static AccessController()
        {
            logger = Esapi.Logger;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorized(object, object)"/>
        public bool IsAuthorized(object action, object resource)
        {
            string userName = Membership.GetUser().UserName;
            return IsAuthorized(userName, action, resource);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorized(object, object, object)"/>
        public bool IsAuthorized(object subject, object action, object resource)
        {
            Hashtable subjects = (Hashtable)resourceToSubjectsMap[resource];
            return (subjects != null && subjects[subject] != null && ((ArrayList)subjects[subject]).Contains(action));
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.AddRule(object, object, object)"/>
        public void AddRule(object subject, object action, object resource)
        {
            if (resourceToSubjectsMap[resource] == null)
            {
                resourceToSubjectsMap[resource] = new Hashtable();
            }
            Hashtable subjects = (Hashtable)resourceToSubjectsMap[resource];
            if (subjects[subject] == null)
            {
                subjects[subject] = new ArrayList();
            }
            ArrayList actions = (ArrayList)subjects[subject];
            if (!actions.Contains(action))
            {
                actions.Add(action);
            }
            else
            {                
                string message = "Attempt to add an access control rule that already exists.";
                throw new EnterpriseSecurityException(message, message);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.RemoveRule(object, object, object)"/>
        public void RemoveRule(object subject, object action, object resource)
        {
            if (resourceToSubjectsMap[resource] != null)
            {
                Hashtable subjects = (Hashtable)resourceToSubjectsMap[resource];
                if (subjects[subject] != null)
                {
                    ArrayList actions = (ArrayList) subjects[subject];
                    actions.Remove(action);
                    if (actions.Count == 0)
                    {
                        subjects.Remove(subject);
                        if (subjects.Count == 0)
                        {
                            resourceToSubjectsMap.Remove(resource);
                        }
                    }
                    return;
                }
            }
            string message = "Attempt to remove an access control rule that does not exist.";
            throw new EnterpriseSecurityException(message, message);
        }
    }
}
