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
}
