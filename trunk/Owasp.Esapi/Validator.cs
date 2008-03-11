/// <summary> OWASP Enterprise Security API .NET (Esapi.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (Esapi) project. For details, please see
/// http://www.owasp.org/Esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The Esapi is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using HttpInterfaces;
using System.Web;
using System.Collections;
using System.IO;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Errors;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Text;
using System.Collections.Specialized;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the IValidator interface. This implementation
    /// relies on the Esapi Encoder, .NET Regular Expressions, Date,
    /// and several other classes to provide basic validation functions. This library
    /// has a heavy emphasis on whitelist validation and canonicalization. All double-encoded
    /// characters, even in multiple encoding schemes, such as [PRE]&amp;lt;[/PRE] or
    /// [PRE]%26lt;[PRE] or even [PRE]%25%26lt;[/PRE] are disallowed.
    /// 
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=Esapi.NET question">Alex Smolen</a> at <a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IValidator">
    /// </seealso>
    public class Validator : IValidator
    {
        /// <summary>The logger. </summary>
        private static readonly Logger logger;

        /// <summary>
        /// Empty constructor
        /// </summary>
        public Validator()
        {
        }

        /// <summary> Validates data received from the browser and returns a safe version. Only
        /// URL encoding is supported. Double encoding is treated as an attack.
        /// 
        /// </summary>                        
        /// <param name="context">The validation context.</param>
        /// <param name="type">The type of data to validate.</param>
        /// <param name="input">The data to validate.</param>
        /// <returns>The canonicalized input.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidDataFromBrowser(string, string, string)">
        /// </seealso>        
        public string GetValidDataFromBrowser(string context, string type, string input)
        {
            try
            {
                string canonical = Esapi.Encoder().Canonicalize(input);

                if (input == null)
                    throw new ValidationException("Bad input", type + " (" + context + ") input to validate was null");

                if (type == null)
                    throw new ValidationException("Bad input", type + " (" + context + ") type to validate against was null");

                Regex regex = ((SecurityConfiguration)Esapi.SecurityConfiguration()).GetValidationPattern(type);
                if (input == null)
                    throw new ValidationException("Bad input", type + " (" + context + ") type to validate against not configured in Esapi.properties");

                if (!regex.IsMatch(canonical))
                    throw new ValidationException("Bad input", type + " (" + context + "=" + input + ") input did not match type definition " + input);

                // if everything passed, then return the canonical form
                return canonical;
            }
            catch (EncodingException ee)
            {
                throw new ValidationException("Internal error", "Error canonicalizing user input", ee);
            }
        }


        /// <summary> Returns true if data received from browser is valid. Only URL encoding is
        /// supported. Double encoding is treated as an attack.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="type">The type of data to validate.</param>
        /// <param name="data">The data to validate.</param>
        /// <returns>Boolean value indicating whether or not the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidDataFromBrowser(string, string, string)">
        /// </seealso>
        public bool IsValidDataFromBrowser(string context, string type, string data)
        {
            try
            {
                GetValidDataFromBrowser(context, type, data);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
        ///    Implementation of GetValidDate
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="format">The DateTimeFormat object to use.</param>        
        /// <returns>DateTime object with value of date.</returns>        
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidDate(string, string, DateTimeFormatInfo)">
        /// </seealso>
        public DateTime GetValidDate(string context, string input, DateTimeFormatInfo format)
        {
            try
            {
                DateTime date = DateTime.Parse(input, format);
                return date;
            }
            catch (Exception e)
            {
                throw new ValidationException("Invalid date", "Problem parsing date (" + context + "=" + input + ") ", e);
            }
        }

        /// <summary>
        ///   Implementation of IsValidCreditCard
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="data">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidCreditCard(string, string)">
        /// </seealso>
        public bool IsValidCreditCard(string context, string data)
        {
            try
            {
                string canonical = GetValidDataFromBrowser(context, "CreditCard", data);

                // perform Luhn algorithm checking
                StringBuilder digitsOnly = new StringBuilder();
                char c;
                for (int i = 0; i < canonical.Length; i++)
                {
                    c = canonical[i];
                    if (Char.IsDigit(c))
                    {
                        digitsOnly.Append(c);
                    }
                }

                int sum = 0;
                int digit = 0;
                int addend = 0;
                bool timesTwo = false;

                for (int i = digitsOnly.Length - 1; i >= 0; i--)
                {
                    digit = Int32.Parse(digitsOnly.ToString(i, i + 1));
                    if (timesTwo)
                    {
                        addend = digit * 2;
                        if (addend > 9)
                        {
                            addend -= 9;
                        }
                    }
                    else
                    {
                        addend = digit;
                    }
                    sum += addend;
                    timesTwo = !timesTwo;
                }

                int modulus = sum % 10;
                return modulus == 0;
            }
            catch (Exception e)
            {
                throw new IntrusionException("Invalid credit card number", "Exception during credit card validation", e);
            }
        }

        /// <summary> Returns true if the directory path (not including a filename) is valid.
        /// 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="dirpath">The directory to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidDirectoryPath(string, string)">
        /// </seealso>
        public bool IsValidDirectoryPath(string context, string dirpath)
        {
            try
            {
                string canonical = Esapi.Encoder().Canonicalize(dirpath);

                // get the canonical path without the drive letter if present
                string cpath = new FileInfo(canonical).FullName.Replace("\\", "/");
                string temp = cpath.ToLower();
                if (temp.Length >= 2 && temp[0] >= 'a' && temp[0] <= 'z' && temp[1] == ':')
                {
                    cpath = cpath.Substring(2);
                }

                // prepare the input without the drive letter if present
                string escaped = canonical.Replace("\\", "/");
                temp = escaped.ToLower();
                if (temp.Length >= 2 && temp[0] >= 'a' && temp[0] <= 'z' && temp[1] == ':')
                {
                    escaped = escaped.Substring(2);
                }

                // the path is valid if the input matches the canonical path
                return escaped.Equals(cpath.ToLower());
            }
            catch (IOException e)
            {
                return false;
            }
            catch (EncodingException ee)
            {
                throw new IntrusionException("Invalid directory", "Exception during directory validation", ee);
            }
        }


        /// <summary>
        ///   Implementation of IsValidFileContent. This just checks the file size right now.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="content">The file content to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidFileContent(string, byte[])">
        /// </seealso>
        public bool IsValidFileContent(string context, byte[] content)
        {
            // FIXME: AAA - temporary - what makes file content valid? Maybe need a parameter here?
            long length = Esapi.SecurityConfiguration().AllowedFileUploadSize;
            return (content.Length < length);
            // FIXME: log something?
        }


        
        //FIXME: AAA - getValidFileName eliminates %00 and other injections.
        //FIXME: AAA - this method should check for %00 injection too
        /// <summary>
        ///   Implementation of IsValidFileName. Detects path manipulation and validates file extension.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The filename to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidFileName(string, string)">
        /// </seealso>
        public  bool IsValidFileName(string context, string input)
        {
            if (input == null || input.Length == 0)
                return false;

            // detect path manipulation
            try
            {
                string canonical = Esapi.Encoder().Canonicalize(input);

                FileInfo f = new FileInfo(canonical);
                string c = f.FullName;
                string cpath = c.Substring(c.LastIndexOf(Path.DirectorySeparatorChar.ToString()) + 1);
                if (!input.Equals(cpath))
                {
                    // FIXME: AAA should this validation really throw an IntrusionException?
                    throw new IntrusionException("Invalid filename", "Invalid filename (" + canonical + ") doesn't match canonical path (" + cpath + ") and could be an injection attack");
                }
            }
            catch (IOException e)
            {
                throw new IntrusionException("Invalid filename", "Exception during filename validation", e);
            }
            catch (EncodingException ee)
            {
                throw new IntrusionException("Invalid filename", "Exception during filename validation", ee);
            }

            // verify extensions
            IList extensions = Esapi.SecurityConfiguration().AllowedFileExtensions;
            IEnumerator i = extensions.GetEnumerator();            
            while (i.MoveNext())
            {                
                string ext = (string)i.Current;
                if (input.ToLower().EndsWith(ext.ToLower()))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        ///  Implementaiton of IsValidFileUpload(). Checks if directory path is valid and file name is valid and file content is valid.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="filepath">The file path.</param>
        /// <param name="filename">The file name.</param>
        /// <param name="content">The contents of the file.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidFileUpload(string, string, string, byte[])">
        /// </seealso>
        public  bool IsValidFileUpload(string context, string filepath, string filename, byte[] content)
        {
            return IsValidDirectoryPath(context, filepath) && IsValidFileName(context, filename) && IsValidFileContent(context, content);
        }

        /// <summary> Validate the parameters, cookies, and headers in an HTTP request against
        /// specific regular expressions defined in the SecurityConfiguration. Note
        /// that IsValidDataFromBrowser uses the Encoder.Canonicalize() method to ensure
        /// that allbool IsValidHttpRequest(IHttpRequest request); encoded characters are reduced to their simplest form, and that any
        /// double-encoded characters are detected and throw an exception.
        /// </summary>
        /// <param name="request">The IHttpRequest object to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidHttpRequest(IHttpRequest)">
        /// </seealso>
        public bool IsValidHttpRequest(IHttpRequest request)
        {
            bool result = true;
            IEnumerator i1 = request.Params.GetEnumerator();
            while (i1.MoveNext())
            {                
                string name = (string) i1.Current;
                if (!IsValidDataFromBrowser("http", "HTTPParameterName", name))
                {
                    // logger.logCritical(Logger.SECURITY, "Parameter name (" + name + ") violates global rule" );
                    result = false;
                }
                // Note: There are no array of values returned from the request parameter, just a single value.

                string value = request.Params[name];
                if (!IsValidDataFromBrowser(name, "HTTPParameterValue", value))
                {
                    // logger.logCritical(Logger.SECURITY, "Parameter value (" + name + "=" + value + ") violates global rule" );
                    result = false;
                }

            }

            if (request.Cookies != null)
            {                
                foreach (String name in request.Cookies)
                {                                                            
                    if (!IsValidDataFromBrowser("http", "HTTPCookieName", name))
                    {
                        // logger.logCritical(Logger.SECURITY, "Cookie name (" + name + ") violates global rule" );
                        result = false;
                    }

                    string cookieValue = request.Cookies[name].Value;
                    if (!IsValidDataFromBrowser(name, "HTTPCookieValue", cookieValue))
                    {
                        // logger.logCritical(Logger.SECURITY, "Cookie value (" + name + "=" + value + ") violates global rule" );
                        result = false;
                    }
                }
            }

            IEnumerator e = request.Headers.GetEnumerator();            
            while (e.MoveNext())
            {                
                string name = (string)e.Current;
                if (name != null && !name.ToUpper().Equals("Cookie".ToUpper()))
                {
                    if (!IsValidDataFromBrowser("http", "HTTPHeaderName", name))
                    {
                        // logger.logCritical(Logger.SECURITY, "Header name (" + name + ") violates global rule" );
                        result = false;
                    }

                    IEnumerator e2 = request.Headers.Keys.GetEnumerator();                    
                    while (e2.MoveNext())
                    {                        
                        string headerValue = (string)e2.Current;
                        if (!IsValidDataFromBrowser(name, "HTTPHeaderValue", headerValue))
                        {                            
                            result = false;
                        }
                    }
                }
            }
            return result;
        }

        /// <summary>
        ///  Implmementation of IsValidListItem. This simply validates whether the value is in the list.
        /// </summary>
        /// <param name="list">The list to validate against.</param>
        /// <param name="listValue">The value to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidListItem(IList, string)">
        /// </seealso>
        public bool IsValidListItem(IList list, string listValue)
        {
            return list.Contains(listValue);
        }

        /// <summary>
        ///   Implementation of IsValidNumber. Checks if number can be properly parsed as a double.
        /// </summary>        
        /// <param name="input">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidNumber(string)">
        /// </seealso>
        public  bool IsValidNumber(string input)
        {
            try
            {
                double d = System.Double.Parse(input);
                return (!Double.IsInfinity(d) && !Double.IsNaN(d));
            }
            catch (FormatException e)
            {
                return false;
            }
        }


        /// <summary>
        ///  Implementation of IsValidParameterSet. This expects the Authenticator context to be set. 
        /// </summary>
        /// <param name="requiredNames">The list of names that are required to exist.</param>
        /// <param name="optionalNames">The list of names that may or may not exist.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidParameterSet(ArrayList, ArrayList)">
        /// </seealso>
        public bool IsValidParameterSet(ArrayList requiredNames, ArrayList optionalNames)
        {
            IHttpRequest request = ((Authenticator)Esapi.Authenticator()).CurrentRequest;

            ArrayList actualNames = new ArrayList(request.Params.Keys);

            // verify ALL required parameters are present            
            ArrayList missing = (ArrayList) requiredNames.Clone();
            IEnumerator i = actualNames.GetEnumerator();
            while (i.MoveNext())
            {
                missing.Remove(i.Current);
            }
            
            if (missing.Count > 0)
            {
                return false;
            }

            // verify ONLY optional + required parameters are present            
            ArrayList extra = (ArrayList)actualNames.Clone();
            IEnumerator iRequired = requiredNames.GetEnumerator();
            while (iRequired.MoveNext())
            {
                extra.Remove(iRequired.Current);
            }
            IEnumerator iOptional = optionalNames.GetEnumerator();
            while (iOptional.MoveNext())
            {
                extra.Remove(iOptional.Current);
            }            

            if (extra.Count > 0)
            {
                return false;
            }
            return true;
        }

        /// <summary> Checks that all bytes are valid ASCII characters (between 33 and 126
        /// inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.       
        /// </summary>
        /// <param name="input">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidPrintable(byte[])">
        /// </seealso>
        public bool IsValidPrintable(byte[] input)
        {
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] < 33 || input[i] > 126)
                    return false;
            }
            return true;
        }

        /// <summary>
        ///   Implementation of IsValidPrintable
        /// </summary>
        /// <param name="input">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidPrintable(string)">
        /// </seealso>
        public bool IsValidPrintable(string input)
        {
            try
            {
                string canonical = Esapi.Encoder().Canonicalize(input);
                System.Text.ASCIIEncoding  encoding = new System.Text.ASCIIEncoding();                
                return IsValidPrintable(encoding.GetBytes(canonical));
            }
            catch (EncodingException ee)
            {
                logger.LogError(ILogger_Fields.SECURITY, "Could not canonicalize user input", ee);
                return false;
            }
        }

        /// <summary>
        ///   Implementation of IsValidRedirectLocation
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="location">The redirect location to validate.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidRedirectLocation(string, string)">        
        /// </seealso>
        public bool IsValidRedirectLocation(string context, string location)
        {
            // FIXME: ENHANCE - it's too hard to put valid locations in as regex
            return Esapi.Validator().IsValidDataFromBrowser(context, "Redirect", location);
        }

        /// <summary>
        ///   Implementation of IsValidSafeHTML. Should be updated to use Anti-SAMY
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidSafeHtml(string, string)">        
        /// </seealso>
        public bool IsValidSafeHtml(string context, string input)
        {
            try
            {
                string canonical = Esapi.Encoder().Canonicalize(input);
                // FIXME: AAA this is just a simple blacklist test - will use Anti-SAMY
                return !(canonical.IndexOf("<scri") > -1) && !(canonical.IndexOf("onload") > -1);
            }
            catch (EncodingException ee)
            {
                throw new IntrusionException("Invalid input", "EncodingException during HTML validation", ee);
            }
        }

        /// <summary>
        ///   Implementation of GetValidSafeHtml. Not implemented.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <returns>String value with safe HTML based on input.</returns>        
        public  string GetValidSafeHtml(string context, string input)
        {
            throw new System.NotSupportedException();
            /**
            AntiSamy as = new AntiSamy();
            try {
            CleanResults test = as.scan(input);
            // OutputFormat format = new OutputFormat(test.getCleanXMLDocumentFragment().getOwnerDocument());
            // format.setLineWidth(65);
            // format.setIndenting(true);
            // format.setIndent(2);
            // format.setEncoding(AntiSamyDOMScanner.ENCODING_ALGORITHM);
            return(test.getCleanHTML().trim());
            } catch (ScanException e) {
            throw new ValidationException( "Invalid HTML", "Problem parsing HTML (" + context + "=" + input + ") ",e );
            } catch (PolicyException e) {
            throw new ValidationException( "Invalid HTML", "HTML violates policy (" + context + "=" + input + ") ",e );
            }
            **/
        }


        /// <summary> Implementation of SafeReadLine.
        /// This implementation reads until a newline or the specified number of
        /// characters.
        /// 
        /// </summary>
        /// <param name="inStream">The stream value to read from.</param>
        /// <param name="max">The maximum bytes to read from the stream.</param>
        /// <returns>The line read from the stream.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.SafeReadLine(Stream, int)">
        /// </seealso>
        public string SafeReadLine(Stream inStream, int max)
        {
            if (max <= 0)
                throw new ValidationAvailabilityException("Invalid input", "Must read a positive number of bytes from the stream");

            StringBuilder sb = new StringBuilder();
            int count = 0;
            int c;

            // FIXME: AAA - verify this method's behavior exactly matches BufferedReader.readLine()
            // so it can be used as a drop in replacement.
            try
            {
                while (true)
                {
                    c = inStream.ReadByte();
                    if (c == -1)
                    {
                        if (sb.Length == 0)
                            return null;
                        break;
                    }
                    if (c == '\n' || c == '\r')
                        break;
                    count++;
                    if (count > max)
                    {
                        throw new ValidationAvailabilityException("Invalid input", "Read more than maximum characters allowed (" + max + ")");
                    }
                    sb.Append((char)c);
                }
                return sb.ToString();
            }
            catch (IOException e)
            {
                throw new ValidationAvailabilityException("Invalid input", "Problem reading from input stream", e);
            }
        }

        /// <summary>
        ///   Static constructor
        /// </summary>
        static Validator()
        {
            logger = Logger.GetLogger("Esapi", "Validator");
        }


    }
}
