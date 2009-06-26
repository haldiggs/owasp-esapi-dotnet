/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/Category:ESAPI.
/// 
/// Copyright (c) 2009 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the BSD. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen
/// </author>
/// <created>  2008 </created>

using System;
using Owasp.Esapi.Interfaces;
using System.IO;
using System.Collections;
using Owasp.Esapi.Errors;
using System.Web.Security;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the IAccessController interface.
    /// </summary>
    /// <author>  <a href="mailto:me@alexsmolen.com?subject=.NET+ESAPI question">Alex Smolen</a> at <a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> February 20, 2008
    /// </since>
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
