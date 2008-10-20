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
using System.Collections;
using System.IO;

namespace Owasp.Esapi.Interfaces
{

    /// <summary> The Executor interface is used to run an OS command with less security risk.
    /// Implementations should do as much as possible to minimize the risk of
    /// injection into either the command or parameters. In addition, implementations
    /// should timeout after a specified time period in order to help prevent denial
    /// of service attacks. The class should perform logging and error handling as
    /// well. Finally, implementation should handle errors and generate an
    /// ExecutorException with all the necessary information.
    /// [P]
    /// [img src="doc-files/Executor.jpg" height="600">
    /// [P]
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    public interface IExecutor
    {

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
        string ExecuteSystemCommand(FileInfo executable, IList parameters, FileInfo workdir, int timeoutSeconds);
    }
}
