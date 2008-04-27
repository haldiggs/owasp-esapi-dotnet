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

using System;
using System.Collections;
using System.IO;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Errors;
using System.Text;
using System.Diagnostics;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the Executor interface. This implementation is very restrictive. Commands must exactly
    /// equal the canonical path to an executable on the system. Valid characters for parameters are alphanumeric,
    /// forward-slash, and dash.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="IExecutor">
    /// </seealso>   
    public class Executor : IExecutor
    {
 
        private static readonly Logger logger;
        
        /// <summary> Public constructor for Executor.
        /// 
        /// </summary>
        public Executor()
        {
        }

            
        // TODO: Push to configuration? 
        /// <summary>
        /// Maximum legal system command size 
        /// </summary>
        private readonly int MAX_SYSTEM_COMMAND_LENGTH = 2500;
    
        

        /// <summary> Executes a system command after checking that the executable exists and
        /// that the parameters have not been subject to injection with untrusted
        /// user data. Implementations shall change to the specified working
        /// directory before invoking the command. Also, processes should be
        /// interrupted after the specified timeout period has elapsed.
        /// 
        /// </summary>
        /// <param name="executable">The command to execute.
        /// </param>
        /// <param name="parameters">The parameters to the command.
        /// </param>
        /// <param name="workdir">The working directory.
        /// </param>
        /// <param name="timeoutSeconds">The timeout, in seconds.        
        /// </param>
        /// <returns> The output of the command
        /// </returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IExecutor.ExecuteSystemCommand(FileInfo, IList, FileInfo, int)"/>
        public string ExecuteSystemCommand(FileInfo executable, IList parameters, FileInfo workdir, int timeoutSeconds)
        {
            StreamReader br = null;
            try
            {
                logger.LogTrace(ILogger_Fields.SECURITY, "Initiating executable: " + executable + " " + parameters.ToString() + " in " + workdir);
                IValidator validator = Esapi.Validator();

                // command must exactly match the canonical path and must actually exist on the file system
                if (!executable.FullName.Equals(executable.FullName))
                {
                    throw new ExecutorException("Execution failure", "Invalid path to executable file: " + executable);
                }
                bool tmpBool;
                if (File.Exists(executable.FullName))
                    tmpBool = true;
                else
                    tmpBool = Directory.Exists(executable.FullName);
                if (!tmpBool)
                {
                    throw new ExecutorException("Execution failure", "No such executable: " + executable);
                }

                // parameters must only contain alphanumerics, dash, and forward slash
                // FIXME: ENHANCE make configurable regexes? Update comments!
                IEnumerator i = parameters.GetEnumerator();                
                while (i.MoveNext())
                {                    
                    string param = (System.String)i.Current;
                    if (!validator.IsValidInput("fixme", "SystemCommand", param, MAX_SYSTEM_COMMAND_LENGTH, false))
                    {
                        throw new ExecutorException("Execution failure", "Illegal characters in parameter to executable: " + param);
                    }
                }

                // working directory must exist
                bool tmpBool2;
                if (File.Exists(workdir.FullName))
                    tmpBool2 = true;
                else
                    tmpBool2 = Directory.Exists(workdir.FullName);
                if (!tmpBool2)
                {
                    throw new ExecutorException("Execution failure", "No such working directory for running executable: " + workdir.FullName);
                }
                                
                ProcessStartInfo processStartInfo = new ProcessStartInfo();
                processStartInfo.CreateNoWindow = true;
                processStartInfo.FileName = executable.FullName;
                processStartInfo.Arguments = parameters.ToString();
                processStartInfo.RedirectStandardOutput = true;
                processStartInfo.UseShellExecute = false;
                Process process = Process.Start(processStartInfo);

                logger.LogTrace(ILogger_Fields.SECURITY, "System command successful: " + parameters.ToString());
                return process.StandardOutput.ReadToEnd();
            }
            catch (Exception e)
            {                
                throw new ExecutorException("Execution failure", "Exception thrown during execution of system command: " + e.Message, e);
            }
            finally
            {
                try
                {
                    if (br != null)
                    {
                        br.Close();
                    }
                }
                catch (IOException e)
                {
                    // give up
                }
            }
        }

        /// <summary>
        /// Static constructor.
        /// </summary>
        static Executor()
        {
            logger = Logger.GetLogger("ESAPI", "Executor");
        }
    }
}
