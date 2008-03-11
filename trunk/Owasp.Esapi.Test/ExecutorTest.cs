/// <summary> OWASP Enterprise Security API .NET (ESAPI.NET) 
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>
/// 
using System;
using NUnit.Framework;
using System.Collections;
using System.IO;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.Test
{
    /// <summary> The Class ExecutorTest.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    [TestFixture]
    public class ExecutorTest
    {
        /// <summary> Instantiates a new executor test.
        /// 
        /// </summary>
        public ExecutorTest():this(null)
        {
        }

        /// <summary> Instantiates a new executor test.
        /// 
        /// </summary>
        /// <param name="testName">the test name
        /// </param>
        public ExecutorTest(string testName)
        {
        }

        /// <summary> Test of ExecuteOSCommand method, of class
        /// Owasp.Esapi.ServicesUtilities.
        /// 
        /// </summary>
        /// <throws>  Exception </throws>
        /// <summary>             the exception
        /// </summary>
        [Test]
        public void Test_ExecuteSystemCommand()
        {
            System.Console.Out.WriteLine("ExecuteSystemCommand");
            IExecutor executor = Esapi.Executor();
            FileInfo executable = new FileInfo("C:\\Windows\\System32\\cmd.exe");
            FileInfo working = new FileInfo("C:\\");
            System.Collections.IList params_Renamed = new ArrayList();
            try
            {
                params_Renamed.Add("/C");
                params_Renamed.Add("dir");
                string result = executor.ExecuteSystemCommand(executable, new ArrayList(params_Renamed), working, 10);
                Assert.IsTrue(result.Length > 0);
            }
            catch (System.Exception e)
            {
                Assert.Fail();
            }
            try
            {
                FileInfo exec2 = new FileInfo(executable.FullName + ";inject.exe");
                executor.ExecuteSystemCommand(exec2, new ArrayList(params_Renamed), working, 10);
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
            try
            {
                FileInfo exec2 = new FileInfo(executable.FullName + "\\..\\cmd.exe");
                executor.ExecuteSystemCommand(exec2, new ArrayList(params_Renamed), working, 10);
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
            try
            {
                FileInfo workdir = new FileInfo("ridiculous");
                executor.ExecuteSystemCommand(executable, new ArrayList(params_Renamed), workdir, 10);
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
            try
            {
                params_Renamed.Add("&dir");
                executor.ExecuteSystemCommand(executable, new ArrayList(params_Renamed), working, 10);
                Assert.Fail();
            }
            catch (System.Exception e)
            {
                // expected
            }
        }
    }
}
