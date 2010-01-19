using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Principal;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;
using EM = Owasp.Esapi.Resources.Errors;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController"/>
    /// <summary>
    /// Reference implementation of the <see cref="Owasp.Esapi.Interfaces.IAccessController"/> interface. It simply
    /// stores the access control rules in nested collections.
    /// </summary>
    public class AccessController : IAccessController
    {
        private Dictionary<object, Dictionary<object, ArrayList>> resourceToSubjectsMap;
        
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
            IPrincipal currentUser = Esapi.SecurityConfiguration.CurrentUser;

            if (currentUser == null || currentUser.Identity == null) {
                throw new EnterpriseSecurityException(EM.AccessControl_NoCurrentUser, EM.AccessControl_NoCurrentUser);
            }

            return IsAuthorized(currentUser.Identity.Name, action, resource);
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorized(object, object, object)"/>
        public bool IsAuthorized(object subject, object action, object resource)
        {
            if (subject == null || action == null || resource == null) {
                throw new ArgumentNullException();
            }

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
            if (subject == null || action == null || resource == null) {
                throw new ArgumentNullException();
            }

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
                throw new EnterpriseSecurityException(EM.AcessControl_AddDuplicateRule, 
                                EM.AcessControl_AddDuplicateRule);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.IAccessController.RemoveRule(object, object, object)"/>
        public void RemoveRule(object subject, object action, object resource)
        {
            if (subject == null || action == null || resource == null) {
                throw new ArgumentNullException();
            }

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

            throw new EnterpriseSecurityException(EM.AccessControl_RemoveInvalidRule, 
                                EM.AccessControl_RemoveInvalidRule);
        }
    }
}
