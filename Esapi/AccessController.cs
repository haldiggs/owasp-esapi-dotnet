using System.Collections;
using System.Web.Security;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Errors;
using System.Collections.Generic;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController"/>
    /// <remarks>
    /// Reference implementation of the <see cref="Owasp.Esapi.Interfaces.IAccessController"/> interface. It simply
    /// stores the access control rules in nested collections.
    /// </remarks>
    public class AccessController : IAccessController
    {
        private Dictionary<object, Dictionary<object, ArrayList>> resourceToSubjectsMap;
        
        /// <summary>The logger.</summary>
        private static readonly ILogger logger = Esapi.Logger;
        
        /// <summary> 
        /// Default constructor.        
        /// </summary>        
        public AccessController()
        {
            resourceToSubjectsMap = new Dictionary<object, Dictionary<object, ArrayList>>();
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
            Dictionary<object, ArrayList> subjects;            

            if (resourceToSubjectsMap.TryGetValue(resource, out subjects)) {
                ArrayList actions;

                if (subjects.TryGetValue(subject, out actions)) {
                    return actions.Contains(action);
                }
            }

            return false;
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.AddRule(object, object, object)"/>
        public void AddRule(object subject, object action, object resource)
        {
            Dictionary<object, ArrayList> subjects;            
            if (!resourceToSubjectsMap.TryGetValue(resource, out subjects)) {
                subjects = new Dictionary<object,ArrayList>();
                resourceToSubjectsMap[resource] = subjects;
            }

            ArrayList actions;
            if (!subjects.TryGetValue(subject, out actions)) {
                actions = new ArrayList();
                subjects[subject] = actions;
            }

            if (!actions.Contains(action)) {
                actions.Add(action);
            }
            else {                
                string message = "Attempt to add an access control rule that already exists.";
                throw new EnterpriseSecurityException(message, message);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.RemoveRule(object, object, object)"/>
        public void RemoveRule(object subject, object action, object resource)
        {
            Dictionary<object, ArrayList> subjects;

            if (resourceToSubjectsMap.TryGetValue(resource, out subjects)) {
                ArrayList actions;

                if (subjects.TryGetValue(subject, out actions)) {
                    if (actions.Contains(action)) {
                        actions.Remove(action);

                        if (actions.Count == 0) {
                            subjects.Remove(actions);

                            if (subjects.Count == 0) {
                                resourceToSubjectsMap.Remove(subjects);
                            }
                        }

                        return;
                    }
                }
            }

            string ruleNotFound = "Attempt to remove an access control rule that does not exist.";
            throw new EnterpriseSecurityException(ruleNotFound, ruleNotFound);
        }
    }
}
