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

namespace Owasp.Esapi
{
    /// <summary>
    /// This class provides accessor methods for the various ESAPI implementations.
    /// </summary>
    public class Esapi
    {
        // TODO - Make these properties?
        
        ///// <param name="accessController">the AccessController to set
        ///// </param>
        //public static IAccessController AccessController
        //{
        //    set
        //    {
        //        Esapi.accessController = value;
        //    }
			
        //}
        ///// <param name="authenticator">the authenticator to set
        ///// </param>
        //public static IAuthenticator Authenticator
        //{
        //    set
        //    {
        //        Esapi.authenticator = value;
        //    }
			
        //}
        ///// <param name="encoder">the encoder to set
        ///// </param>
        //public static IEncoder Encoder
        //{
        //    set
        //    {
        //        Esapi.encoder = value;
        //    }
			
        //}
        ///// <param name="encryptor">the encryptor to set
        ///// </param>
        //public static IEncryptor Encryptor
        //{
        //    set
        //    {
        //        Esapi.encryptor = value;
        //    }
			
        //}
        ///// <param name="executor">the executor to set
        ///// </param>
        //public static IExecutor Executor
        //{
        //    set
        //    {
        //        Esapi.executor = value;
        //    }
			
        //}
        ///// <param name="httpUtilities">the httpUtilities to set
        ///// </param>
        //public static IHttpUtilities HttpUtilities
        //{
        //    set
        //    {
        //        Esapi.httpUtilities = value;
        //    }
			
        //}
        ///// <param name="intrusionDetector">the intrusionDetector to set
        ///// </param>
        //public static IIntrusionDetector IntrusionDetector
        //{
        //    set
        //    {
        //        Esapi.intrusionDetector = value;
        //    }
			
        //}
        ///// <param name="randomizer">the randomizer to set
        ///// </param>
        //public static IRandomizer Randomizer
        //{
        //    set
        //    {
        //        Esapi.randomizer = value;
        //    }
			
        //}
        ///// <param name="securityConfiguration">the securityConfiguration to set
        ///// </param>
        //public static ISecurityConfiguration SecurityConfiguration
        //{
        //    set
        //    {
        //        Esapi.securityConfiguration = value;
        //    }
			
        //}
        ///// <param name="validator">the validator to set
        ///// </param>
        //public static IValidator Validator
        //{
        //    set
        //    {
        //        Esapi.validator = value;
        //    }
			
        //}
		
		private static IAccessController accessController = null;
		
		private static IAuthenticator authenticator = null;
		
		private static IEncoder encoder = null;
		
		private static IEncryptor encryptor = null;
		
		private static IExecutor executor = null;
		
		private static IHttpUtilities httpUtilities = null;
		
		private static IIntrusionDetector intrusionDetector = null;
		
		//    private static ILogger logger = null;
		
		private static IRandomizer randomizer = null;
		
		private static ISecurityConfiguration securityConfiguration = null;
		
		private static IValidator validator = null;
		
		/// <summary> prevent instantiation of this class</summary>
		private Esapi()
		{
		}
		
		/// <summary>
        ///     The access controller accessor.
        /// </summary>
        /// <returns> The access controller implementation
		/// </returns>		
        public static IAccessController AccessController()
		{
			if (Esapi.accessController == null)
				Esapi.accessController = new AccessController();
			return Esapi.accessController;
		}
		
        /// <summary>
        ///      The authenticator accessor.
        /// </summary>
		/// <returns> The authenticator implementation.
		/// </returns>
		public static IAuthenticator Authenticator()
		{
			if (Esapi.authenticator == null)
				Esapi.authenticator = new Authenticator();
			return Esapi.authenticator;
		}

        /// <summary>
        ///      The encoder accessor.
        /// </summary>
        /// <returns> The encoder implementation.
        /// </returns>
		public static IEncoder Encoder()
		{
			if (Esapi.encoder == null)
				Esapi.encoder = new AntiXssEncoder();
			return Esapi.encoder;
		}

        /// <summary>
        ///      The encryptor accessor.
        /// </summary>
        /// <returns> The encryptor implementation.
        /// </returns>
		public static IEncryptor Encryptor()
		{
			if (Esapi.encryptor == null)
				Esapi.encryptor = new Encryptor();
			return Esapi.encryptor;
		}

        /// <summary>
        ///      The executor accessor.
        /// </summary>
        /// <returns> The executor implementation.
        /// </returns>
		public static IExecutor Executor()
		{
			if (Esapi.executor == null)
				Esapi.executor = new Executor();
			return Esapi.executor;
		}

        /// <summary>
        ///      The HTTP utilities accessor.
        /// </summary>
        /// <returns> The HTTP utilities implementation.
        /// </returns>
		public static IHttpUtilities HttpUtilities()
		{
			if (Esapi.httpUtilities == null)
				Esapi.httpUtilities = new HttpUtilities();
			return Esapi.httpUtilities;
		}

        /// <summary>
        ///      The intrusion detector accessor.
        /// </summary>
        /// <returns> The intrusion detector implementation.
        /// </returns>
		public static IIntrusionDetector IntrusionDetector()
		{
			if (Esapi.intrusionDetector == null)
				Esapi.intrusionDetector = new IntrusionDetector();
			return Esapi.intrusionDetector;
		}
		
		//    /**
		//     * @return the logger
		//     */
		//    public static  ILogger getLogger() {
		//        if (Esapi.logger == null)
		//            return Logger();
		//        return Esapi.logger;
		//    }
		//
		//    /**
		//     * @param logger the logger to set
		//     */
		//    public static  void setLogger(ILogger logger) {
		//        Esapi.logger = logger;
		//    }
		//
        /// <summary>
        ///      The randomzier accessor.
        /// </summary>
        /// <returns> The randomizer implementation.
        /// </returns>
		public static IRandomizer Randomizer()
		{
			if (Esapi.randomizer == null)
				Esapi.randomizer = new Randomizer();
			return Esapi.randomizer;
		}

        /// <summary>
        ///      The security configuration accessor.
        /// </summary>
        /// <returns> The security configuration implementation.
        /// </returns>
		public static ISecurityConfiguration SecurityConfiguration()
		{
			if (Esapi.securityConfiguration == null)
				Esapi.securityConfiguration = new SecurityConfiguration();
			return Esapi.securityConfiguration;
		}

        /// <summary>
        ///      The validator accessor.
        /// </summary>
        /// <returns> The validator implementation.
        /// </returns>
		public static IValidator Validator()
		{
			if (Esapi.validator == null)
				Esapi.validator = new Validator();
			return Esapi.validator;
		}
	}
}