/// <summary> OWASP Enterprise Security API .NET (ESAPI.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>


using System;
using System.Collections;
using System.IO;
using Owasp.Esapi.Interfaces;
using System.Collections.Specialized;
using Owasp.Esapi.Errors;
using System.Configuration;
using System.Xml.Serialization;
using System.Xml;
using System.Xml.Schema;

namespace Owasp.Esapi
{

    /// <summary> Reference implementation of the IEncryptedProperties interface. This
    /// implementation wraps a normal properties file, and creates surrogates for the
    /// GetProperty and SetProperty methods that perform encryption and decryption based on the Encryptor.
    /// A very simple Main program is provided that can be used to create an
    /// encrypted properties file. A better approach would be to allow unencrypted
    /// properties in the file and to encrypt them the first time the file is
    /// accessed.
    /// 
    /// </summary>
    /// <author>  Alex Smolen (alex.smolen@foundstone.com)
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptedProperties">
    /// </seealso>
    [Serializable]        
    public class EncryptedProperties:IEncryptedProperties, IXmlSerializable
    {
        /// <summary>The properties. </summary>

        private NameValueCollection properties = new NameValueCollection();

        /// <summary>The logger. </summary>
        private static readonly Logger logger;

        /// <summary> Instantiates a new encrypted properties.</summary>
        public EncryptedProperties()
        {
            // hidden
        }

        /// <summary> Gets the property value from the encrypted store, decrypts it, and returns the 
        /// plaintext value to the caller.
        /// </summary>
        /// <param name="key">The key for the property key/value pair.
        /// </param>
        /// <returns> The property (decrypted).
        /// </returns>       
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptedProperties.GetProperty(string)">
        /// </seealso>
        public string GetProperty(string key)
        {
            lock (this)
            {
                try
                {
                    return Esapi.Encryptor().Decrypt(properties.Get(key));
                }
                catch (Exception e)
                {
                    throw new EncryptionException("Property retrieval failure", "Couldn't decrypt property", e);
                }
            }
        }

        /// <summary> Encrypts the plaintext property value and stores the ciphertext value in the encrypted store.        
        /// </summary>
        /// <param name="key">The key for the property key/value pair.
        /// </param>
        /// <param name="value">The value to set the property to.
        /// </param>
        /// <returns> The value the property was set to.
        /// </returns>   
        /// <seealso cref="Owasp.Esapi.Interfaces.IEncryptedProperties.SetProperty(string, string)">
        /// </seealso>
        public virtual string SetProperty(string key, string value)
        {
            lock (this)
            {
                try
                {
                    object tempObject;                    
                    tempObject = properties[key];
                    properties[key] = Esapi.Encryptor().Encrypt(value);
                    return (string)tempObject;
                }
                catch (Exception e)
                {
                    throw new EncryptionException("Property setting failure", "Couldn't encrypt property", e);
                }
            }
        }

        /// <summary> Return the key set for the properties key/value pairs.
        /// 
        /// </summary>
        /// <returns> The KeySet values.
        /// </returns>
        public virtual IList KeySet()
        {
            return new ArrayList(properties.Keys);
        }

        #region IXmlSerializable Members

        XmlSchema IXmlSerializable.GetSchema()
        {
            return null;
        }

        void IXmlSerializable.ReadXml(XmlReader reader)
        {
            this.properties = new NameValueCollection();
            XmlReader read2 = reader;
            while (reader.Read())
            {
                if (reader.Name.Equals("property"))
                { 
                    reader.MoveToFirstAttribute();
                    this.properties.Add(reader.Name, reader.Value);
                }
            }            
        }

        void IXmlSerializable.WriteXml(XmlWriter writer)
        {
            foreach (string key in this.properties.Keys)
            {
                writer.WriteStartElement("property");
                string value = this.properties[key];
                writer.WriteAttributeString(key, value);
                writer.WriteEndElement();
            }
        }

        #endregion



        /// <summary> Loads the properties from a stream.
        /// 
        /// </summary>
        /// <param name="inStream">The stream to read the file in from.
        /// </param>
        public void Load(Stream inStream)
        {
            try
            {
                StreamReader sw = new StreamReader(inStream);
                XmlSerializer xs = new XmlSerializer(typeof(EncryptedProperties));
                EncryptedProperties props = (EncryptedProperties) xs.Deserialize(sw);
                this.properties = props.properties;                
                logger.LogTrace(ILogger_Fields.SECURITY, "Encrypted properties loaded successfully");
            }
            catch (Exception e)
            {
                logger.LogError(ILogger_Fields.SECURITY, "Encrypted properties could not be loaded successfully", e);
            }
            finally 
            {
                inStream.Close();
            }
        }

        /// <summary> Store the encrypted properties to a stream.        
        /// </summary>
        /// <param name="outStream">The stream to store the properties to.
        /// </param>
        /// <param name="comments">The comments to store with the properties file.        
        /// </param>
        public virtual void Store(Stream outStream, string comments)
        {
            try
            {
                    StreamWriter sw = new StreamWriter(outStream);
                    XmlSerializer xs = new XmlSerializer(typeof(EncryptedProperties));
                    xs.Serialize(sw, this);
                    logger.LogTrace(ILogger_Fields.SECURITY, "Encrypted properties stored successfully");
                
            }
            catch
            {
            }
            finally
            {
                outStream.Close();
            }
        }

        /// <summary> The main method for reading in an out encrypted properties.
        /// </summary>
        /// <param name="args">The arguments (standard for main method).
        /// </param>
        [STAThread]
        public static void Main(string[] args)
        {
            // FIXME: AAA verify that this still works
            FileInfo f = new FileInfo(args[0]);
            Logger.GetLogger("EncryptedProperties", "main").LogDebug(ILogger_Fields.SECURITY, "Loading encrypted properties from " + f.FullName);
            bool tmpBool;
            if (File.Exists(f.FullName))
                tmpBool = true;
            else
                tmpBool = Directory.Exists(f.FullName);
            if (!tmpBool)
                throw new IOException("Properties file not found: " + f.FullName);
            Logger.GetLogger("EncryptedProperties", "main").LogDebug(ILogger_Fields.SECURITY, "Encrypted properties found in " + f.FullName);
            EncryptedProperties ep = new EncryptedProperties();            
            FileStream inStream = new FileStream(f.FullName, FileMode.Open, FileAccess.Read);
            ep.Load(inStream);
            
            StreamReader br = new StreamReader(System.Console.OpenStandardInput());
            string key = null;
            do
            {
                System.Console.Out.Write("Enter key: ");
                key = br.ReadLine();
                System.Console.Out.Write("Enter value: ");
                string value_Renamed = br.ReadLine();
                if (key != null && key.Length > 0 && value_Renamed.Length > 0)
                {
                    ep.SetProperty(key, value_Renamed);
                }
            }
            while (key != null && key.Length > 0);
            
            FileStream out_Renamed = new FileStream(f.FullName, FileMode.Create);
            ep.Store(out_Renamed, "Encrypted Properties File");
            out_Renamed.Close();

            IEnumerator i = ep.KeySet().GetEnumerator();           
            while (i.MoveNext())
            {                
                string k = (string)i.Current;
                string value_Renamed = ep.GetProperty(k);
                System.Console.Out.WriteLine("   " + k + "=" + value_Renamed);
            }
        }
        static EncryptedProperties()
        {
            logger = Logger.GetLogger("ESAPI", "Encrypted Properties");
        }
    }
}
