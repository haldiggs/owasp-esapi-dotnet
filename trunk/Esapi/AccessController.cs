using System.Collections;
using System.Web.Security;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the IAccessController interface.
    /// </summary>
    /// <seealso cref="Owasp.Esapi.Interfaces.IAccessController">
    /// </seealso>
    public class AccessController : IAccessController
    {
        private Hashtable resourceToSubjectsMap = new Hashtable();

        /// <summary>The logger.</summary>
        private static readonly ILogger logger;
        
        /// <summary> 
        /// AccessController constructor.        
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

        public bool IsAuthorized(object action, object resource)
        {
            string userName = Membership.GetUser().UserName;
            return IsAuthorized(userName, action, resource);
        }

        public bool IsAuthorized(object subject, object action, object resource)
        {
            Hashtable subjects = (Hashtable)resourceToSubjectsMap[resource];
            return (subjects != null && subjects[subject] != null && ((ArrayList)subjects[subject]).Contains(action));
        }

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
                logger.Warning(LogEventTypes.FUNCTIONALITY, "Attempt to add an access control rule that already exists.");
            }
        }

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
            logger.Warning(LogEventTypes.FUNCTIONALITY, "Attempt to remove an access control rule that does not exist.");
        }
    }
}
