using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// Addin element collection
    /// </summary>
    public abstract class AddinElementCollection : ConfigurationElementCollection
    {
        #region Assemblies Property

        /// <summary>
        /// The XML name of the <see cref="Assemblies"/> property.
        /// </summary>
        internal const string AssembliesPropertyName = "assemblies";

        /// <summary>
        /// Gets or sets the Assemblies.
        /// </summary>
        [ConfigurationProperty(AssembliesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public AddinAssemblyCollection Assemblies
        {
            get
            {
                return (AddinAssemblyCollection)base[AssembliesPropertyName];
            }
            set
            {
                base[AssembliesPropertyName] = value;
            }
        }

        #endregion
    }
}
