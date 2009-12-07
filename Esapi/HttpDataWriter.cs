using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;

namespace Owasp.Esapi
{
    /// <summary>
    /// HTTP data writer
    /// </summary>
    internal class HttpDataWriter
    {
        private TextWriter _output  = null;
        private bool _insideSection = false;
        private bool _hasValues     = false;

        protected HttpDataWriter(TextWriter output)
        {
            if (output == null) {
                throw new ArgumentNullException("output");
            }
            _output = output;
        }

        /// <summary>
        /// Write header
        /// </summary>
        /// <param name="text"></param>
        protected void WriteHeader(string text)
        {
            _output.Write(text + ": ");
        }
        /// <summary>
        /// Write footer
        /// </summary>
        protected void WriteFooter()
        {
            if (_insideSection) {
                _output.Write(") ");
            }
        }
        /// <summary>
        /// Start new data section
        /// </summary>
        /// <param name="name"></param>
        protected void WriteSection(string name)
        {
            if (_insideSection) {
                _output.Write(") ");
                _insideSection = false;
                _hasValues = false;
            }

            _output.Write(" (" + name + ": ");
            _insideSection = !string.IsNullOrEmpty(name);
        }
        /// <summary>
        /// Write value
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        protected void WriteValue(string name, string value)
        {
            _output.Write(string.Format("{0}\"{1}\"=\"{2}\"", _hasValues ? ", " : "",  name, value));
            _hasValues = true;
        }
        /// <summary>
        /// Write value collection
        /// </summary>
        /// <param name="values"></param>
        protected void WriteValues(NameValueCollection values)
        {
            if (values != null) {
                foreach (string name in values.Keys) {
                    WriteValue(name, values[name]);
                }
            }
        }
        /// <summary>
        /// Write value
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <param name="obfuscatedValues">Parameter names whose values are obfuscated</param>
        protected void WriteObfuscatedValue(string name, string value, ICollection<string> obfuscatedValues)
        {
            string obfuscatedValue = value;
            if (obfuscatedValues != null && obfuscatedValues.Contains(name)) {
                obfuscatedValue = "********";
            }
            WriteValue(name, obfuscatedValue);
        }
        /// <summary>
        /// Write values
        /// </summary>
        /// <param name="values"></param>
        /// <param name="obfuscatedValues">Parameter names whose values are obfuscated</param>
        protected void WriteObfuscatedValues(NameValueCollection values, ICollection<string> obfuscatedValues)
        {
            if (values != null) {
                foreach (string name in values.Keys) {
                    WriteObfuscatedValue(name, values[name], obfuscatedValues);
                }
            }
        }
    }
}
