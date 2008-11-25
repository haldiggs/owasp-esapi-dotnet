/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/.NET_ESAPI.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using Owasp.Esapi.Interfaces;
using System.IO;
using System.Collections;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the IAccessController interface. This reference
    /// implementation uses a simple model for specifying a set of access control
    /// rules. Many organizations will want to create their own implementation of the
    /// methods provided in the IAccessController interface.
    /// 
    /// This reference implementation uses a simple scheme for specifying the rules.
    /// The first step is to create a namespace for the resources being accessed. For
    /// files and URL's, this is easy as they already have a namespace. Be extremely
    /// careful about canonicalizing when relying on information from the user in an
    /// access control decision.
    /// 
    /// For functions, data, and services, you will have to come up with your own
    /// namespace for the resources being accessed. You might simply define a flat
    /// namespace with a list of category names. For example, you might specify
    /// 'FunctionA', 'FunctionB', and 'FunctionC'. Or you can create a richer
    /// namespace with a hierarchical structure, such as:
    /// 
    /// /functions
    /// purchasing
    /// shipping
    /// inventory
    /// 
    /// /admin
    /// createUser
    /// deleteUser
    /// 
    /// Once you've defined your namespace, you have to work out the rules that
    /// govern access to the different parts of the namespace. This implementation
    /// allows you to attach a simple access control list (ACL) to any part of the
    /// namespace tree. The ACL lists a set of roles that are either allowed or
    /// denied access to a part of the tree. You specify these rules in a textfile
    /// with a simple format.
    /// 
    /// There is a single configuration file supporting each of the five methods in
    /// the IAccessController interface. These files are located in the ESAPI
    /// resources directory as specified when the CLR was started. The use of a
    /// default deny rule is STRONGLY recommended. The file format is as follows:
    /// 
    /// <pre>
    /// path          | role,role   | allow/deny | comment
    /// ------------------------------------------------------------------------------------
    /// /banking/*    | user,admin  | allow      | authenticated users can access /banking
    /// /admin        | admin       | allow      | only admin role can access /admin
    /// /             | any         | deny       | default deny rule
    /// </pre>
    /// 
    /// To find the matching rules, the four mapping rules are used in the following order:
    /// <ul>
    /// <li>exact match, e.g. /access/login</li>
    /// <li>longest path prefix match, beginning / and ending /*, e.g. /access/* or /*</li>
    /// <li>extension match, beginning *., e.g. *.css</li>S
    /// <li>default rule, specified by the single character pattern /</li>
    /// </ul>
    /// 
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=.NET+ESAPI question">Alex Smolen</a> at <a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IAccessController">
    /// </seealso>
    
    public class AccessController:IAccessController
    {
        /// <summary> 
        /// AccessController constructor.        
        /// </summary>        
        public AccessController()
        {
        }

        private void InitBlock()
        {
            
        }

        /// <summary>The resource directory. </summary>        
        private static readonly FileInfo resourceDirectory;

        /// <summary>The url map. </summary>
        private IDictionary urlMap = new Hashtable();

        /// <summary>The function map. </summary>        
        private IDictionary functionMap = new Hashtable();

        /// <summary>The data map. </summary>
        private IDictionary dataMap = new Hashtable();

        /// <summary>The file map. </summary>        
        private IDictionary fileMap = new Hashtable();

        /// <summary>The service map. </summary>        
        private IDictionary serviceMap = new Hashtable();

        /// <summary>The deny. </summary>        
        private Rule deny = new Rule();

        /// <summary>The logger. </summary>        
        private static ILogger logger;
        
        // FIXME: consider adding flag for logging
        // FIXME: perhaps an enumeration for context (i.e. the layer the call is made from)

        /// <summary> Returns true if an account is authorized to access the referenced URL. The implementation should allow
        /// access to be granted to any part of the URI.
        /// 
        /// </summary>
        /// <param name="url">The url.
        /// </param>
        /// <returns> true, if the user is authorized for the URL.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorizedForUrl(string)">
        /// </seealso>
        public bool IsAuthorizedForUrl(string url)
        {
            if (urlMap.Count == 0)
            {
                urlMap = LoadRules(new FileInfo(resourceDirectory.FullName + "\\" + "URLAccessRules.txt"));
            }
            return MatchRule(urlMap, url);
        }

        /// <summary> Returns true if an account is authorized to access the referenced function. The implementation should define the
        /// function "namespace" to be enforced. Choosing something simple like the classname of action classes or menu item
        /// names will make this implementation easier to use.
        /// 
        /// </summary>
        /// <param name="functionName">The function name.
        /// </param>
        /// <returns> true, if the user is authorized for the function.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorizedForFunction(string)">
        /// </seealso>
        public bool IsAuthorizedForFunction(string functionName)
        {
            try
            {
                AssertAuthorizedForFunction(functionName);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary> Returns true if an account is authorized to access the referenced data. The implementation should define the data
        /// "namespace" to be enforced.
        /// 
        /// </summary>
        /// <param name="key">The key.
        /// </param>
        /// <returns> true, if the user is authorized for the data.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorizedForData(string)">
        /// </seealso>
        public bool IsAuthorizedForData(string key)
        {
            try
            {
                AssertAuthorizedForData(key);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary> Returns true if an account is authorized to access the referenced file. The implementation should be extremely careful
        /// about canonicalization.
        /// 
        /// </summary>
        /// <param name="filepath">The filepath.
        /// </param>
        /// <returns> true, if the user is authorized for the file.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorizedForFile(string)">
        /// </seealso>
        public bool IsAuthorizedForFile(string filepath)
        {
            try
            {
                AssertAuthorizedForFile(filepath);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary> Returns true if an account is authorized to access the referenced service. This can be used in applications that
        /// provide access to a variety of backend services.
        /// 
        /// </summary>
        /// <param name="serviceName">The service name.
        /// </param>
        /// <returns> true, if the user is authorized for the service.
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IAccessController.IsAuthorizedForService(string)">
        /// </seealso>
        public bool IsAuthorizedForService(string serviceName)
        {
            try
            {
                AssertAuthorizedForService(serviceName);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }



        public void AssertAuthorizedForUrl(String url)
        {
            if (urlMap == null || urlMap.Count == 0)
            {
                urlMap = LoadRules(new FileInfo(resourceDirectory + "\\" + "URLAccessRules.txt"));
            }
            if (!MatchRule(urlMap, url))
            {
                throw new AccessControlException("Not authorized for URL", "Not authorized for URL: " + url);
            }
        }


        public void AssertAuthorizedForFunction(String functionName)
        {
            if (functionMap == null || functionMap.Count == 0)
            {
                functionMap = LoadRules(new FileInfo(resourceDirectory + "\\" + "FunctionAccessRules.txt"));
            }
            if (!MatchRule(functionMap, functionName))
            {
                throw new AccessControlException("Not authorized for function", "Not authorized for function: " + functionName);
            }
        }


        public void AssertAuthorizedForData(String key)
        {
            if (dataMap == null || dataMap.Count == 0)
            {
                dataMap = LoadRules(new FileInfo(resourceDirectory + "\\" + "DataAccessRules.txt"));
            }
            if (!MatchRule(dataMap, key))
            {
                throw new AccessControlException("Not authorized for function", "Not authorized for data: " + key);
            }
        }

        public void AssertAuthorizedForFile(String filepath)
        {
            if (fileMap == null || fileMap.Count == 0)
            {
                fileMap = LoadRules(new FileInfo(resourceDirectory + "\\" + "FileAccessRules.txt"));
            }
            // FIXME: AAA think about canonicalization here - use file canonicalizer
            // remember that Windows paths have \ instead of /
            if (!MatchRule(fileMap, filepath.Replace("\\\\", "/")))
            {
                throw new AccessControlException("Not authorized for file", "Not authorized for file: " + filepath);
            }
        }


        public void AssertAuthorizedForService(String serviceName)
        {
            if (serviceMap == null || serviceMap.Count == 0)
            {
                serviceMap = LoadRules(new FileInfo(resourceDirectory + "\\" + "ServiceAccessRules.txt"));
            }
            if (!MatchRule(serviceMap, serviceName))
            {
                throw new AccessControlException("Not authorized for service", "Not authorized for service: " + serviceName);
            }
        }
        



        /// <summary> Match a rule, based on a path.
        /// 
        /// </summary>
        /// <param name="map">The map of rules.
        /// </param>
        /// <param name="path">The path to check.
        /// 
        /// </param>
        /// <returns> true, if the rule is matched.        
        /// </returns>
        private bool MatchRule(IDictionary map, string path)
        {
            // get users roles
            IUser user = Esapi.Authenticator().GetCurrentUser();
            IList roles = user.Roles;
            // search for the first rule that matches the path and rules
            Rule rule = SearchForRule(map, roles, path);
            return rule.allow;
        }

        /// <summary> Search for rule. Four mapping rules are used in order: - exact match,
        /// e.g. /access/login - longest path prefix match, beginning / and ending
        /// /*, e.g. /access/* or /* - extension match, beginning *., e.g. *.css -
        /// default servlet, specified by the single character pattern /
        /// 
        /// </summary>
        /// <param name="map">The map of rules.
        /// </param>
        /// <param name="roles">The roles associated with the subject.
        /// </param>
        /// <param name="path">The path to check.
        /// 
        /// </param>
        /// <returns> The rule to match.
        /// 
        /// </returns>
        private Rule SearchForRule(IDictionary map, IList roles, string path)
        {
            string canonical = null;
            try
            {
                canonical = Esapi.Encoder().Canonicalize(path);
            }
            catch (EncodingException ee)
            {
                logger.Warning(LogEventTypes.SECURITY, "Failed to canonicalize input: " + path);
            }

            string part = canonical;
            while (part.EndsWith("/"))
            {
                part = part.Substring(0, (part.Length - 1) - (0));
            }

            if (part.IndexOf("..") != -1)
            {
                throw new IntrusionException("Attempt to manipulate access control path", "Attempt to manipulate access control path: " + path);
            }

            // extract extension if any
            string extension = "";
            int extIndex = part.LastIndexOf(".");
            if (extIndex != -1)
            {
                extension = part.Substring(extIndex + 1);
            }

            // Check for exact match - ignore any ending slash
            Rule rule = (Rule)map[part];

            // Check for ending with /*
            if (rule == null)
                rule = (Rule)map[part + "/*"];

            // Check for matching extension rule *.ext
            if (rule == null)
                rule = (Rule)map["*." + extension];

            // if rule found and user's roles match rules' roles, return the rule
            if (rule != null && Overlap(rule.roles, roles))
                return rule;

            // return default deny, if rule can't be found.
            if (!part.Contains("/"))
            {
                return deny;
            }
            
            // if rule has not been found, strip off the last element and recurse
            part = part.Substring(0, (part.LastIndexOf('/')) - (0));

            // return default deny
            if (part.Length <= 1)
            {
                return deny;
            }

            return SearchForRule(map, roles, part);
        }

        /// <summary> Return true if there is overlap between the two sets of roles.
        /// 
        /// </summary>
        /// <param name="ruleRoles">The rule roles.
        /// </param>
        /// <param name="userRoles">The user roles.
        /// 
        /// </param>
        /// <returns> true, if there is overlap.
        /// </returns>
        private bool Overlap(IList ruleRoles, IList userRoles)
        {
            if (ruleRoles.Contains("any"))
            {
                return true;
            }
            IEnumerator i = userRoles.GetEnumerator();            
            while (i.MoveNext())
            {                
                string role = (string)i.Current;
                if (ruleRoles.Contains(role))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary> Load the rules from a file.
        /// 
        /// </summary>
        /// <param name="f">The file to load the rules from.
        /// 
        /// </param>
        /// <returns> The dictionary containing the rules.
        /// 
        /// </returns>
        private IDictionary LoadRules(FileInfo f)
        {            
            IDictionary map = new Hashtable();
            FileStream fis = null;
            try
            {
                fis = new FileStream(f.FullName, FileMode.Open, FileAccess.Read);
                string line = "";
                while ((line = Esapi.Validator().SafeReadLine(fis, 500)) != null)
                {
                    if (line.Length > 0 && line[0] != '#')
                    {
                        Rule rule = new Rule();
                        string[] parts = line.Split(new string[] {"|"}, StringSplitOptions.None);
                        // fix Windows paths
                        rule.path = parts[0].Trim().Replace("\\", "/");
                        rule.roles.Add(parts[1].Trim().ToLower());
                        string action = parts[2].Trim();
                        rule.allow = action.ToUpper().Equals("allow".ToUpper());
                        if (map.Contains(rule.path))
                        {
                            logger.Warning(LogEventTypes.SECURITY, "Problem in access control file. Duplicate rule ignored: " + rule);
                        }
                        map[rule.path] = rule;
                    }
                }
                return map;
            }
            catch (Exception e)
            {
                logger.Warning(LogEventTypes.SECURITY, "Problem in access control file", e);
            }
            finally
            {
                try
                {
                    if (fis != null)
                    {
                        fis.Close();
                    }
                }
                catch (IOException e)
                {
                    logger.Warning(Owasp.Esapi.Interfaces.LogEventTypes.SECURITY, "Failure closing access control file: " + f, e);
                }
            }
            return map;
        }
        
        /// <summary> The Rule class.</summary>
        private class Rule
        {
            /// <summary>The path. </summary>
            protected internal string path = "";

            /// <summary>The roles. </summary>            
            protected internal IList roles = new ArrayList();

            /// <summary>The allow. </summary>
            protected internal bool allow = false;

            public override string ToString()
            {
                return "URL:" + path + " | " + roles.ToString() + " | " + (allow ? "allow" : "deny");
            }
        }

        /// <summary>
        /// Static constructor.
        /// </summary>
        static AccessController()
        {
            resourceDirectory = ((SecurityConfiguration)Esapi.SecurityConfiguration()).ResourceDirectory;
            logger = Esapi.Logger();
        }

    }
}
