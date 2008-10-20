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
using NUnit.Framework;
using System.Collections;
using Owasp.Esapi.Errors;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class AccessReferenceMapTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class AccessReferenceMapTest
    {

        /// <summary> Instantiates a new access reference map test.
        /// 
        /// </summary>
        public AccessReferenceMapTest():this(null)
        {
            
        }


        /// <summary> Instantiates a new access reference map test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public AccessReferenceMapTest(string testName)            
        {
        }

        
        /// <summary> Test of Update method, of class Owasp.Esapi.AccessReferenceMap.
        /// 
        /// </summary>
        /// <throws>  AuthenticationException </throws>
        /// <summary>             the authentication exception
        /// </summary>
        [Test]
        public void Test_Update()
        {
            System.Console.Out.WriteLine("Update");
            AccessReferenceMap arm = new AccessReferenceMap();
            String pass = Esapi.Authenticator().GenerateStrongPassword();
            IUser u = Esapi.Authenticator().CreateUser("armUpdate", pass, pass);

            // test to make sure update returns something
            arm.Update(Esapi.Authenticator().GetUserNames());
            String indirect = arm.GetIndirectReference(u.AccountName);
            if (indirect == null)
            {
                Assert.Fail();
            }

            // test to make sure update removes items that are no longer in the list
            Esapi.Authenticator().RemoveUser(u.AccountName);
            arm.Update(Esapi.Authenticator().GetUserNames());
            indirect = arm.GetIndirectReference(u.AccountName);
            if (indirect != null)
            {
                Assert.Fail();
            }
            // test to make sure old indirect reference is maintained after an update
            arm.Update(Esapi.Authenticator().GetUserNames());
            String newIndirect = arm.GetIndirectReference(u.AccountName);
            Assert.AreEqual(indirect, newIndirect);
        }


        /// <summary> Test of Iterator method, of class Owasp.Esapi.AccessReferenceMap.</summary>        
        [Test]
        public void Test_Iterator()
        {
            System.Console.Out.WriteLine("Iterator");
            AccessReferenceMap arm = new AccessReferenceMap();
            arm.Update(Esapi.Authenticator().GetUserNames());

            IEnumerator i = arm.Enumerator();            
            while (i.MoveNext())
            {            
                String userName = (string)i.Current;
                IUser u = Esapi.Authenticator().GetUser(userName);
                System.Console.Out.WriteLine(">>>" + u);
                if (u == null)
                {
                    Assert.Fail();
                }                    
            }
        }

        /// <summary> Test of getIndirectReference method, of class
        /// Owasp.Esapi.AccessReferenceMap.
        /// </summary>        
        [Test]
        public void Test_GetIndirectReference()
        {
            System.Console.Out.WriteLine("GetIndirectReference");

            string directReference = "234";            
            ArrayList list = new ArrayList();
            list.Add("123");
            list.Add(directReference);
            list.Add("345");
            AccessReferenceMap accessReferenceMap = new AccessReferenceMap(list);

            String expResult = directReference;
            String result = accessReferenceMap.GetIndirectReference(directReference);
            Assert.AreNotSame(expResult, result);
        }

        /// <summary> Test of getDirectReference method, of class
        /// Owasp.Esapi.AccessReferenceMap.
        /// 
        /// </summary>
        /// <throws>  AccessControlException </throws>
        /// <summary>             the access control exception
        /// </summary>
        
        [Test]
        public void Test_GetDirectReference()
        {
            System.Console.Out.WriteLine("GetDirectReference");

            string directReference = "234";           
            ArrayList list = new ArrayList();
            list.Add("123");
            list.Add(directReference);
            list.Add("345");
            AccessReferenceMap accessReferenceMap = new AccessReferenceMap(list);

            String ind = accessReferenceMap.GetIndirectReference(directReference);
            String dir = (String)accessReferenceMap.GetDirectReference(ind);
            Assert.AreEqual(directReference, dir);
            try
            {
                accessReferenceMap.GetDirectReference("invalid");
                Assert.Fail();
            }
            catch (AccessControlException e)
            {
                // success
            }
        }


    }
}
