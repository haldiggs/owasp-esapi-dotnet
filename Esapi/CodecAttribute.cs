using System;

namespace Owasp.Esapi
{
    /// <summary>
    /// Codec attribute
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class CodecAttribute : Attribute
    {
        private readonly string _name;
        private bool _autoLoad;
     
        /// <summary>
        /// Initialize codec attribute
        /// </summary>
        /// <param name="name">Codec unique name</param>
        public CodecAttribute(string name)
        {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("name");
            }
            _name     = name;
            _autoLoad = true;
        }

        /// <summary>
        /// Codec unique name
        /// </summary>
        public string Name
        {
            get { return _name; }
        }

        /// <summary>
        /// Codec can be loaded automatically
        /// </summary>
        /// <remarks>Set to false if the codec requires initialization parameters</remarks>
        public bool AutoLoad
        {
            get { return _autoLoad;  }
            set { _autoLoad = value; }
        }
    }
}
