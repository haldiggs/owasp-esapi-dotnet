using System;
using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;
using Owasp.Esapi.Configuration;
using System.Collections.Generic;
using System.Configuration;

namespace Owasp.Esapi
{
    /// <summary>
    /// Addin Manager interface
    /// </summary>
    /// <typeparam name="TAddin">Addin type</typeparam>
    internal interface IAddinManager<TAddin>
       where TAddin : class
    {
        /// <summary>
        /// Add addin
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        void Add(string name, TAddin value);
        /// <summary>
        /// Clear loaded addins
        /// </summary>
        void Clear();
        /// <summary>
        /// Manager contains addin
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        bool Contains(string key);
        /// <summary>
        /// Remove addin
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        bool Remove(string key);
        /// <summary>
        /// Try get addin 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        bool TryGetAddin(string key, out TAddin value);
    }

    /// <summary>
    /// Addin builder
    /// </summary>
    /// <typeparam name="TAddin"></typeparam>
    internal class AddinBuilder<TAddin>
        where TAddin : class
    {
        /// <summary>
        /// Build addin instance
        /// </summary>
        /// <typeparam name="T">Instance type</typeparam>
        /// <param name="configuration">Instance configuratio</param>
        /// <returns></returns>
        public static TAddin MakeInstance(AddinElement configuration)
        {
            if (configuration == null) {
                throw new ArgumentNullException("configuration");
            }

            // Get type
            Type typeInstance = Type.GetType(configuration.Type, true);

            // Create properties
            Dictionary<string, object> properties = null;
            if (configuration.PropertyValues != null && configuration.PropertyValues.Count > 0) {
                properties = new Dictionary<string, object>();

                foreach (KeyValueConfigurationElement key in configuration.PropertyValues) {
                    properties[key.Key] = key.Value;
                }
            }

            // Construct
            return ObjectBuilder.Build<TAddin>(typeInstance, properties);
        }
    }

    /// <summary>
    /// Addin manager loaded
    /// </summary>
    /// <typeparam name="TAddin">Addin tyep</typeparam>
    internal class AddinManagerLoader<TAddin>
        where TAddin : class
    {
        /// <summary>
        /// Load named addin object
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        private static bool LoadNamedAddin(IAddinManager<TAddin> manager, Type type)
        {
            if (manager == null) {
                throw new ArgumentNullException("manager");
            }
            if (type == null) {
                throw new ArgumentNullException("type");
            }

            bool loaded = false;

            object[] attrs = type.GetCustomAttributes(typeof(AddinAttribute), false);
            if (attrs != null && attrs.Length > 0) {
                AddinAttribute addinAttr = (AddinAttribute)attrs[0];

                if (addinAttr.AutoLoad) {
                    manager.Add(addinAttr.Name, ObjectBuilder.Build<TAddin>(type));
                    loaded = true;
                }
            }

            return loaded;
        }
        /// <summary>
        /// Load named addin objects
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="assembly"></param>
        /// <param name="typeMatch"></param>
        private static void LoadNamedAddins(IAddinManager<TAddin> manager, Assembly assembly, Regex typeMatch)
        {
            if (assembly == null) {
                throw new ArgumentNullException("assembly");
            }
            if (typeMatch == null) {
                throw new ArgumentNullException("typeMatch");
            }

            foreach (Type type in assembly.GetTypes()) {
                if (typeMatch.IsMatch(type.FullName)) {
                    LoadNamedAddin(manager, type);
                }
            }
        }
        /// <summary>
        /// Load addin elements
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="addinElements"></param>
        private static void LoadAddinElements(IAddinManager<TAddin> manager, ICollection addinElements)
        {
            if (addinElements == null) {
                throw new ArgumentNullException();
            }

            foreach (AddinElement addinElement in addinElements) {
                string failMessage = string.Format("Failed to load addin \"{0}\"", addinElement.Name);

                try {
                    manager.Add(addinElement.Name, AddinBuilder<TAddin>.MakeInstance(addinElement));
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, failMessage, exp);
                    throw;
                }
            }
        }
        /// <summary>
        /// Load addin assemblies
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="addinAssemblies"></param>
        private static void LoadAddinAssemblies(IAddinManager<TAddin> manager, AddinAssemblyCollection addinAssemblies)
        {
            // Load actions
            foreach (AddinAssemblyElement addinAssembly in addinAssemblies) {
                try {
                    Assembly assembly = Assembly.Load(addinAssembly.Name);
                    Regex typeMatch = MatchHelper.WildcardToRegex(addinAssembly.Types);

                    LoadNamedAddins(manager, assembly, typeMatch);
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, "Failed to load addin assembly", exp);
                    throw;
                }
            }
        }
        /// <summary>
        /// Load addins
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="addinElements"></param>
        public static void Load(IAddinManager<TAddin> manager, AddinElementCollection addinElements)
        {
            LoadAddinAssemblies(manager, addinElements.Assemblies);
            LoadAddinElements(manager, addinElements);
        }
    }
}
