using System;

namespace Owasp.Esapi
{
    /// <summary>
    /// Codec attribute
    /// </summary>
    /// <remarks>
    /// Marks a class as a codec; the class has to implement ICodec interface
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class CodecAttribute : AddinAttribute
    {
        /// <summary>
        /// Initialize codec attribute
        /// </summary>
        /// <param name="name">Codec unique name</param>
        public CodecAttribute(string name)
            : base(name)
        {
        }
    }
}
