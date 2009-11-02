using System;

namespace Owasp.Esapi
{
    /// <summary>
    /// Named addin attribute
    /// </summary>
    public class AddinAttribute : Attribute
    {
        private readonly string _name;
        private bool _autoLoad;

        /// <summary>
        /// Initialize addin attribute
        /// </summary>
        /// <param name="name">Addin unique name</param>
        public AddinAttribute(string name)
        {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("name");
            }
            _name = name;
            _autoLoad = true;
        }

        /// <summary>
        /// Addin unique name
        /// </summary>
        public string Name
        {
            get { return _name; }
        }

        /// <summary>
        /// Addin can be loaded automatically
        /// </summary>
        /// <remarks>
        /// Set to false if the addin requires initialization parameters
        /// </remarks>
        public bool AutoLoad
        {
            get { return _autoLoad; }
            set { _autoLoad = value; }
        }
    }
}
