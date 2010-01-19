using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration"/>
    /// <summary>
    /// Reference implementation of the <see cref="Owasp.Esapi.Interfaces.ISecurityConfiguration"/> interface
    /// manages all the settings used by the ESAPI in a single place.
    /// </summary>
    /// <remarks>
    /// You must have the relevant configuration in your config file (app.config, web.config). 
    /// See the app.config file in the EsapiTest project for the necessary elements.
    ///  </remarks>
    public class SecurityConfiguration : ISecurityConfiguration
    {
        private SecurityConfigurationElement _settings;

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.MasterPassword"/>
        public string MasterPassword
        {
            get
            {
                return _settings.Encryption.MasterPassword;
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.MasterSalt"/>
        public byte[] MasterSalt
        {
            get
            {
                return Encoding.ASCII.GetBytes(_settings.Encryption.MasterSalt);
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.AllowedFileExtensions"/>
        public IList AllowedFileExtensions
        {
            get
            {
                string[] extensions = _settings.Application.UploadValidExtensions.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                return new List<string>(extensions);                
            }

        }
       
        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.AllowedFileUploadSize"/>
        public int AllowedFileUploadSize
        {
            get
            {
                return _settings.Application.UploadMaxSize;
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.EncryptionAlgorithm"/>
        public string EncryptionAlgorithm
        {
            get
            {
                return _settings.Algorithms.Encryption;
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.HashAlgorithm"/>
        public string HashAlgorithm
        {
            get
            {
                return _settings.Algorithms.Hash;
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.CharacterEncoding"/>
        public string CharacterEncoding
        {
            get
            {
                return _settings.Application.CharacterEncoding;
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.DigitalSignatureAlgorithm"/>
        public string DigitalSignatureAlgorithm
        {
            get
            {
                return _settings.Algorithms.DigitalSignature;
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.RandomAlgorithm"/>
        public string RandomAlgorithm
        {
            get
            {
                return _settings.Algorithms.Random;
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.LogLevel"/>
        public int LogLevel
        {
            get
            {
                return LogLevels.ParseLogLevel(_settings.Application.LogLevel);
            }
        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.LogEncodingRequired"/>
        public bool LogEncodingRequired
        {
            get
            {
                return _settings.Application.LogEncodingRequired;
            }

        }

        /// <inheritdoc cref="Owasp.Esapi.Interfaces.ISecurityConfiguration.CurrentUser"/>
        public IPrincipal CurrentUser
        {
            get
            {
                if (HttpContext.Current != null) {
                    return HttpContext.Current.User;
                }
                return Thread.CurrentPrincipal;
            }
        }

        /// <summary> Instantiates a new configuration.</summary>
        internal SecurityConfiguration(SecurityConfigurationElement settings)
        {
            if (settings == null) {
                throw new ArgumentNullException("settings");
            }

            _settings = settings;
        }        
    }
}
