using System.Configuration;

namespace Owasp.Esapi.Configuration
{
    /// <summary>
    /// The HttpUtilitiesElement Configuration Element.
    /// </summary>
    public class HttpUtilitiesElement : ConfigurationElement
    {
        #region Type Property

        /// <summary>
        /// The XML name of the <see cref="Type"/> property.
        /// </summary>
        internal const string TypePropertyName = "type";

        /// <summary>
        /// Gets or sets the Type.
        /// </summary>
        [ConfigurationProperty(TypePropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public string Type
        {
            get
            {
                return (string)base[TypePropertyName];
            }
            set
            {
                base[TypePropertyName] = value;
            }
        }

        #endregion

    }
}
