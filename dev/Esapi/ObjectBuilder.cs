using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using Owasp.Esapi.Configuration;
using System.Configuration;

namespace Owasp.Esapi
{
    /// <summary>
    /// Object builder
    /// </summary>
    internal class ObjectBuilder
    {        
        /// <summary>
        /// Build object instance
        /// </summary>
        /// <typeparam name="T">Instance type</typeparam>
        /// <param name="typeName">Type to instantiate</param>
        /// <returns></returns>
        public static T Build<T>(string typeName)
            where T : class
        {
            if (string.IsNullOrEmpty(typeName)) {
                throw new ArgumentException("Invalid argument", "typeName");
            }
            return Build<T>(Type.GetType(typeName, true));
        }

        /// <summary>
        /// Build object instance
        /// </summary>
        /// <typeparam name="T">Instance type</typeparam>
        /// <param name="type">Type to instantiate</param>
        /// <returns></returns>
        public static T Build<T>(Type type)
            where T : class
        {
            if (type == null) {
                throw new ArgumentNullException();
            }
            return Activator.CreateInstance(type) as T;
        }

        /// <summary>
        /// Build object instance
        /// </summary>
        /// <typeparam name="T">Instance type</typeparam>
        /// <param name="typeName">Type to instantiate</param>
        /// <param name="properties">Properties to set</param>
        /// <returns></returns>
        public static T Build<T>(string typeName, IDictionary<string, object> properties)
            where T : class
        {
            if (string.IsNullOrEmpty(typeName)) {
                throw new ArgumentException("Invalid argument", "typeName");
            }
            return Build<T>(Type.GetType(typeName, true), properties);
        }

        /// <summary>
        /// Build object instance
        /// </summary>
        /// <typeparam name="T">Instance type</typeparam>
        /// <param name="type">Type to instantiate</param>
        /// <param name="properties">Properties to set</param>
        /// <returns></returns>
        public static T Build<T>(Type type, IDictionary<string, object> properties)
            where T : class
        {
            if (type == null) {
                throw new ArgumentNullException("type");
            }

            T instance = Build<T>(type);
            if (instance != null && properties != null) {
                try {
                    SetProperties(instance, properties);
                }
                catch {
                    instance = null;
                    throw;
                }
            }

            return instance;
        }

        /// <summary>
        /// Build object instance
        /// </summary>
        /// <typeparam name="T">Instance type</typeparam>
        /// <param name="typeName">Type to instantiate</param>
        /// <param name="initParams">Constructor parameters</param>
        /// <param name="properties">Properties to set</param>
        /// <returns></returns>
        public static T Build<T>(string typeName, object[] initParams, IDictionary<string, object> properties)
            where T : class
        {
            if (string.IsNullOrEmpty(typeName)) {
                throw new ArgumentException("Invalid type name", "typeName");
            }

            return Build<T>(Type.GetType(typeName, true), initParams, properties);
        }

        /// <summary>
        /// Build object instance
        /// </summary>
        /// <typeparam name="T">Instance type</typeparam>
        /// <param name="type">Type to instantiate</param>
        /// <param name="initParams">Constructor paremeters</param>
        /// <param name="properties">Properties to set</param>
        /// <returns></returns>
        public static T Build<T>(Type type, object[] initParams, IDictionary<string, object> properties)
            where T : class
        {
            if (type == null) {
                throw new ArgumentNullException("type");
            }

            T instance = (initParams != null && initParams.Length > 0 ?
                Activator.CreateInstance(type, initParams) as T :
                Activator.CreateInstance(type) as T);

            if (instance != null && properties != null) {
                try {
                    SetProperties(instance, properties);
                }
                catch {
                    instance = null;
                    throw;
                }
            }

            return instance;
        }

        /// <summary>
        /// Set instance properties
        /// </summary>
        /// <param name="instance">Object instance</param>
        /// <param name="properties">Properties to set</param>
        private static void SetProperties(object instance, IDictionary<string, object> properties)
        {
            Debug.Assert(instance != null);

            Type instanceType = instance.GetType();

            foreach (string propertyName in properties.Keys) {
                PropertyInfo propertyInfo = instanceType.GetProperty(propertyName);
                if (propertyInfo == null) {
                    throw new ArgumentOutOfRangeException(propertyName);
                }

                propertyInfo.SetValue(instance, properties[propertyName], null);
            }
        }
    }
}
