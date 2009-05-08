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
using System.Web.Security;

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

        /// <summary>
        /// Static constructor.
        /// </summary>
        static AccessController()
        {
            logger = Esapi.Logger;
        }

        /// <summary>The logger. </summary>
        private static readonly ILogger logger;


        public Boolean IsAuthorized(Object key, Object runtimeParameter)
        {
            throw new NotImplementedException();
        }

        public void AssertAuthorized(Object key, Object runtimeParameter)
        {
            throw new NotImplementedException();
        }
    }
}
