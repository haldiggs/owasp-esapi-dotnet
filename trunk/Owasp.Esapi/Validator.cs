/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/.NET_ESAPI.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the LGPL. You should read and accept the
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
using org.owasp.validator.html;

namespace Owasp.Esapi
{
    /// <summary> Reference implementation of the IValidator interface. This implementation
    /// relies on the Esapi Encoder, .NET Regular Expressions, Date,
    /// and several other classes to provide basic validation functions. This library
    /// has a heavy emphasis on whitelist validation and canonicalization. All double-encoded
    /// characters, even in multiple encoding schemes, such as &amp;lt; or
    /// %26lt; or even %25%26lt; are disallowed.
    /// 
    /// </summary>
    /// <author>  <a href="mailto:alex.smolen@foundstone.com?subject=.NET+ESAPI question">Alex Smolen</a> at <a
    /// href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> February 20, 2008
    /// </since>
    /// <seealso cref="Owasp.Esapi.Interfaces.IValidator">
    /// </seealso>
    public class Validator : IValidator
    {
        /// <summary>The logger. </summary>
        private static readonly ILogger logger;

        // constants
    	private static readonly int MAX_CREDIT_CARD_LENGTH = 19;
	    private static readonly int MAX_PARAMETER_NAME_LENGTH = 100;
	    private static readonly int MAX_PARAMETER_VALUE_LENGTH = 10000;
        private AntiSamy antiSamy = new AntiSamy();        
        private Policy policy = Policy.getInstance(((SecurityConfiguration)Esapi.SecurityConfiguration()).ResourceDirectory.FullName + "\\" + "antisamy.xml");
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
        /// <param name="maxLength">The maximum valid length.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>The canonicalized input.</returns>
        /// <seealso cref="IValidator.GetValidInput">
        /// </seealso>        
        public string GetValidInput(string context, string type, string input, int maxLength, bool allowNull)
        {
            try
            {
                context = Esapi.Encoder().Canonicalize(context);
                string canonical = Esapi.Encoder().Canonicalize(input);

                if (IsEmpty(canonical))
                {
                    if (allowNull) return null;
                    throw new ValidationException(context + " is required", type + " (" + context + ") input to validate was null");
                }

                if (canonical.Length > maxLength)
                {
                    //FIXME: ENHANCE if the length is exceeded by a wide margin, throw IntrusionException?
                    throw new ValidationException(context + " can not exceed " + maxLength + " characters", type + " (" + context + "=" + input + ") input exceeds maximum allowed length of " + maxLength + " by " + (canonical.Length - maxLength) + " characters");
                }

                if (type == null)
                    throw new ValidationException(context + " is invalid", type + " (" + context + ") type to validate against was null");

                Regex regex = ((SecurityConfiguration)Esapi.SecurityConfiguration()).GetValidationPattern(type);
                if (regex == null)
                    throw new ValidationException(context + " is invalid", type + " (" + context + ") type to validate against not configured in ESAPI.properties");

                if (!regex.Match(canonical).Success)
                {
                    throw new ValidationException(context + " is invalid", type + " (" + context + "=" + input + ") input did not match type definition " + regex.ToString());
                }
                // if everything passed, then return the canonical form
                return canonical;
            }
            catch (EncodingException ee)
            {
                throw new ValidationException(context + " is invalid", "Error canonicalizing user input", ee);
            }
            
            
            
        }

        /// <summary> Returns true if data received from browser is valid. Only URL encoding is
        /// supported. Double encoding is treated as an attack.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="type">The type of data to validate.</param>
        /// <param name="data">The data to validate.</param>
        /// <param name="maxLength">The maximum valid length.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Boolean value indicating whether or not the data is valid.</returns>
        /// <seealso cref="IValidator.IsValidInput">
        /// </seealso>
        public bool IsValidInput(string context, string type, string data, int maxLength, bool allowNull)
        {
            try
            {
                GetValidInput(context, type, data, maxLength, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }    
        
        /// <summary>
        ///     Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, 
	    ///     and input that is clearly an attack will generate a descriptive IntrusionException.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="format">The DateTimeFormat object to use.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>DateTime object with value of date.</returns>        
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidDate(string, string, DateTimeFormatInfo, bool)">
        /// </seealso>
        public DateTime GetValidDate(string context, string input, DateTimeFormatInfo format, bool allowNull)
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
        ///    Returns true if input is a valid date according to the specified date format.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="format">The DateTimeFormat object to use.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>DateTime object with value of date.</returns>        
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidDate(string, string, DateTimeFormatInfo, bool)">
        /// </seealso>
        public bool IsValidDate(String context, String input, DateTimeFormatInfo format, bool allowNull)
        {
            try
            {
                GetValidDate(context, input, format, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
        

        /// <summary>
        /// Returns a canonicalized and validated credit card number as a String. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 	 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The input to validate.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>String value if the input is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidCreditCard(string, string, bool)">
        /// </seealso>
        public string GetValidCreditCard(string context, string input, bool allowNull)
        {
            if (IsEmpty(input))
            {
                if (allowNull) return null;
                throw new ValidationException(context + " is required", "(" + context + ") input is required");
            }

            String canonical = GetValidInput(context, "CreditCard", input, MAX_CREDIT_CARD_LENGTH, allowNull);

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
                digit = Int32.Parse(digitsOnly.ToString(i, 1));
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
            if (modulus != 0) throw new ValidationException(context + " invalid", context + " invalid");
            return canonical;
        }

        /// <summary>
	    /// Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The input to validate.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>String value if the input is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidCreditCard(string, string, bool)">
        /// </seealso>
        public bool IsValidCreditCard(String context, String input, bool allowNull)
        {
            try
            {
                GetValidCreditCard(context, input, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
        
        
        

        /// <summary> Returns true if the directory path (not including a filename) is valid.
        /// 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The directory to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidDirectoryPath(string, string, bool)">
        /// </seealso>
        public string GetValidDirectoryPath(string context, string input, bool allowNull)
        {
            String canonical = "";
            try
            {
                if (IsEmpty(input))
                {
                    if (allowNull) return null;
                    throw new ValidationException(context + " is required", "(" + context + ") input is required");
                }

                canonical = Esapi.Encoder().Canonicalize(input);

                // do basic validation
                Regex directoryNamePattern = ((SecurityConfiguration)Esapi.SecurityConfiguration()).GetValidationPattern("DirectoryName");
                if (!directoryNamePattern.Match(canonical).Success)
                {
                    throw new ValidationException(context + " is an invalid directory name", "Attempt to use a directory name (" + canonical + ") that violates the global rule in ESAPI.properties (" + directoryNamePattern.ToString() + ")");
                }

                // get the canonical path without the drive letter if present
                String cpath = new DirectoryInfo(input).FullName.Replace("\\", "/");
                String temp = cpath.ToLower();
                if (temp.Length >= 2 && temp[0] >= 'a' && temp[0] <= 'z' && temp[1] == ':')
                {
                    cpath = cpath.Substring(2);
                }

                // prepare the input without the drive letter if present
                String escaped = canonical.Replace("\\", "/");
                temp = escaped.ToLower();
                if (temp.Length >= 2 && temp[0] >= 'a' && temp[0] <= 'z' && temp[1] == ':')
                {
                    escaped = escaped.Substring(2);
                }

                // the path is valid if the input matches the canonical path
                if (!escaped.Equals(cpath.ToLower()))
                {
                    throw new ValidationException(context + " is an invalid directory name", "The input path does not match the canonical path (" + canonical + ")");
                }
            }
            catch (IOException e)
            {
                throw new ValidationException(context + " is an invalid directory name", "Attempt to use a directory name (" + canonical + ") that does not exist");
            }
            catch (EncodingException ee)
            {
                throw new IntrusionException(context + " is an invalid directory name", "Exception during directory validation", ee);
            }
            return canonical;	            
        }
        
        /// <summary> Returns true if the directory path (not including a filename) is valid.
        /// 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The directory to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidDirectoryPath(string, string, bool)">
        /// </seealso>
        public bool IsValidDirectoryPath(String context, String input, bool allowNull)
        {
            try
            {
                GetValidDirectoryPath(context, input, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }



        //FIXME: AAA - getValidFileName eliminates %00 and other injections.
        //FIXME: AAA - this method should check for %00 injection too
        /// <summary>
        /// Returns a canonicalized and validated file name as a String. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The filename to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <returns>String value of the filename, if it is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidFileName(string, string, bool)">
        /// </seealso>
        public string GetValidFileName(string context, string input, bool allowNull)
        // FIXME: check length
        {
            if (IsEmpty(input))
            {
                if (allowNull) return null;
                throw new ValidationException(context + " is required", "(" + context + ") input is required");
            }

            String canonical = "";

            // detect path manipulation
            try
            {
                canonical = Esapi.Encoder().Canonicalize(input);

                // do basic validation
                Regex fileNamePattern = ((SecurityConfiguration)Esapi.SecurityConfiguration()).GetValidationPattern("FileName");
                if (!fileNamePattern.Match(canonical).Success)
                {
                    throw new ValidationException(context + " is an invalid filename", "Attempt to use a filename (" + canonical + ") that violates the global rule in ESAPI.properties (" + fileNamePattern.ToString() + ")");
                }
                FileInfo f = new FileInfo(canonical);
                String c = f.FullName;
                String cpath = c.Substring(c.LastIndexOf(Path.DirectorySeparatorChar) + 1);
                if (!input.Equals(cpath))
                {
                    throw new ValidationException(context + " is an invalid filename", "Invalid filename (" + canonical + ") doesn't match canonical path (" + cpath + ") and could be an injection attack");
                }
            }
            catch (IOException e)
            {
                throw new IntrusionException(context + " is an invalid filename", "Exception during filename validation", e);
            }
            catch (EncodingException ee)
            {
                throw new IntrusionException(context + " is an invalid filename", "Exception during filename validation", ee);
            }

            // verify extensions
            IList extensions = Esapi.SecurityConfiguration().AllowedFileExtensions;
            IEnumerator i = extensions.GetEnumerator();
            while (i.MoveNext())
            {
                String ext = (String)i.Current;
                if (input.ToLower().EndsWith(ext.ToLower()))
                {
                    return canonical;
                }
            }
            throw new IntrusionException(context + " is an invalid filename", "Extension does not exist in EASPI.getAllowedFileExtensions list");
        }


        /// FIXME: AAA - need new method getValidFileName that eliminates %00 and other injections.
        /// FIXME: AAA - this method should check for %00 injection too	
        /// <summary>
        /// Returns true if input is a valid file name.        
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The filename to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <returns>String value of the filename, if it is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidFileName(string, string, bool)">
        /// </seealso>	
        public bool IsValidFileName(String context, String input, bool allowNull)
        {
            try
            {
                GetValidFileName(context, input, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
        /// Returns true if input is a valid number. 
        /// </summary>        
        /// <param name="context">The context for validation.</param>
        /// <param name="input">The data to validate.</param>           
        /// <param name="minValue">The minimum value for the number.</param>
        /// <param name="maxValue">The maximum value for the number.</param>        
        /// <param name="allowNull">Whether or not null data is considered value.</param>     
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidNumber(string, string, long, long, bool)">
        /// </seealso>
        public bool IsValidNumber(String context, String input, long minValue, long maxValue, bool allowNull)
        {
            try
            {
                GetValidNumber(context, input, minValue, maxValue, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }


        /// <summary>
        /// Returns a validated number as a double. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>        
        /// <param name="input">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidNumber(string, string, long, long, bool)">
        /// </seealso>
        public Double GetValidNumber(String context, String input, long minValue, long maxValue, bool allowNull)
        {
            Double minDoubleValue = Convert.ToDouble(minValue);
            Double maxDoubleValue = Convert.ToDouble(maxValue);
            return GetValidDouble(context, input, minDoubleValue, maxDoubleValue, allowNull);
        }

        /// <summary>
        /// Returns true if input is a valid double.
        /// </summary>        
        /// <param name="context">The context for validation.</param>
        /// <param name="input">The data to validate.</param>           
        /// <param name="minValue">The minimum value for the number.</param>
        /// <param name="maxValue">The maximum value for the number.</param>        
        /// <param name="allowNull">Whether or not null data is considered value.</param>     
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidDouble(string, string, double, double, bool)">
        /// </seealso>
        public bool IsValidDouble(String context, String input, double minValue, double maxValue, bool allowNull)
        {
            try
            {
                GetValidDouble(context, input, minValue, maxValue, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
        /// Returns true if input is a valid double.
        /// </summary>        
        /// <param name="context">The context for validation.</param>
        /// <param name="input">The data to validate.</param>           
        /// <param name="minValue">The minimum value for the number.</param>
        /// <param name="maxValue">The maximum value for the number.</param>        
        /// <param name="allowNull">Whether or not null data is considered value.</param>     
        /// <returns>Double if the input is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidDouble(string, string, double, double, bool)">
        /// </seealso>
        public Double GetValidDouble(String context, String input, double minValue, double maxValue, bool allowNull)
        {
            if (minValue > maxValue)
            {
                //should this be an application exception?
                throw new ValidationException("maxValue (" + maxValue + ") must be greater than minValue (" + minValue + ") for " + context, "maxValue (" + maxValue + ") must be greater than minValue (" + minValue + ") for " + context);
            }

            if (IsEmpty(input))
            {
                if (allowNull) return 0;
                throw new ValidationException(context + " is required", context + " is required");
            }

            try
            {
                Double d = Double.Parse(input);
                if (Double.IsInfinity(d)) throw new ValidationException(context + " is an invalid number", "Number (" + input + ") is infinite");
                if (Double.IsNaN(d)) throw new ValidationException(context + " is an invalid number", "Number (" + input + ") is not a number");
                if (d < minValue) throw new ValidationException(context + " must be between " + minValue + " and " + maxValue, "Invalid number (" + input + "). Number must be between " + minValue + " and " + maxValue);
                if (d > maxValue) throw new ValidationException(context + " must be between " + minValue + " and " + maxValue, "Invalid number (" + input + "). Number must be between " + minValue + " and " + maxValue);
                return d;
            }
            catch (FormatException e)
            {
                throw new ValidationException(context + " is an invalid number", "Invalid number format (" + input + ")", e);
            }
        }


        /// <summary>
        /// Returns true if input is a valid integer.
        /// </summary>        
        /// <param name="context">The context for validation.</param>
        /// <param name="input">The data to validate.</param>           
        /// <param name="minValue">The minimum value for the number.</param>
        /// <param name="maxValue">The maximum value for the number.</param>        
        /// <param name="allowNull">Whether or not null data is considered value.</param>     
        /// <returns>Boolean value inidicating if the input is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidInteger(string, string, int, int, bool)">
        /// </seealso>
        public bool IsValidInteger(String context, String input, int minValue, int maxValue, bool allowNull)
        {
            try
            {
                GetValidInteger(context, input, minValue, maxValue, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
	

        /// <summary>
	    /// Returns a validated number as a double. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException.         
	    /// </summary>        
        /// <param name="context">The context for validation.</param>
        /// <param name="input">The data to validate.</param>           
        /// <param name="minValue">The minimum value for the number.</param>
        /// <param name="maxValue">The maximum value for the number.</param>        
        /// <param name="allowNull">Whether or not null data is considered value.</param>     
        /// <returns>Integer if the input is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidInteger(string, string, int, int, bool)">
        /// </seealso>
        public int GetValidInteger(String context, String input, int minValue, int maxValue, bool allowNull)
        {
            if (minValue > maxValue)
            {
                //should this be a RunTime?
                throw new ValidationException("maxValue (" + maxValue + ") must be greater than minValue (" + minValue + ") for " + context, "maxValue (" + maxValue + ") must be greater than minValue (" + minValue + ") for " + context);
            }

            if (IsEmpty(input))
            {
                if (allowNull) { return 0; }
                throw new ValidationException(context + " is required", "Input is required");
            }

            try
            {
                int i = Int32.Parse(input);
                if (i < minValue) throw new ValidationException(context + " must be between " + minValue + " and " + maxValue, "Invalid Integer. Integer must be between " + minValue + " and " + maxValue);
                if (i > maxValue) throw new ValidationException(context + " must be between " + minValue + " and " + maxValue, "Invalid Integer. Integer must be between " + minValue + " and " + maxValue);

                return (Convert.ToInt32(i));
            }
            catch (FormatException e)
            {
                throw new ValidationException(context + " is an invalid integer", "Invalid Integer", e);
            }
        }

        /// <summary>
        /// Returns true if input is valid file content.         
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The file content to validate.</param>
        /// <param name="maxBytes">The maximum amount of bytes to allow.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidFileContents(string, byte[], int, bool)">
        /// </seealso>
        public bool IsValidFileContents(String context, byte[] input, int maxBytes, bool allowNull)
        {
            try {
                GetValidFileContents( context, input, maxBytes, allowNull);
                return true;
            } catch( Exception e )
            {
                return false;
            }
        }

        /// <summary>
	    /// Returns validated file content as a byte array. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException.     
	    /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The file content to validate.</param>
        /// <param name="maxBytes">The maximum amount of bytes to allow.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Byte value if the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidFileContents(string, byte[], int, bool)">
        /// </seealso>
        public byte[] GetValidFileContents(String context, byte[] input, int maxBytes, bool allowNull)
        {
            if (IsEmpty(input))
            {
                if (allowNull) return null;
                throw new ValidationException(context + " is required", "(" + context + ") input is required");
            }

            // FIXME: AAA - temporary - what makes file content valid? Maybe need a parameter here?
            long esapiMaxBytes = Esapi.SecurityConfiguration().AllowedFileUploadSize;
            if (input.Length > esapiMaxBytes) { throw new ValidationException(context + " can not exceed " + esapiMaxBytes + " bytes", "Exceeded ESAPI max length"); }
            if (input.Length > maxBytes)
            {
                throw new ValidationException(context + " can not exceed " + maxBytes + " bytes", "Exceeded maxBytes (" + input.Length + ")");
            }

            return input;
            // FIXME: log something?
        }
      
        /// <summary>
        /// Returns true if a file upload has a valid name, path, and content.        
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="directorypath">The directory path of the file upload.</param>
        /// <param name="filename">The name of the file to upload.</param>
        /// <param name="content">The contents of the file.</param>
        /// <param name="maxBytes">The maximum bytes allowed in the file content.</param>        
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Boolean value indiciating whether the data is valid.</returns>
        /// <seealso cref="IValidator.IsValidFileUpload(string, string, string, byte[], int, bool)">
        /// </seealso>
        public bool IsValidFileUpload(String context, String directorypath, String filename, byte[] content, int maxBytes, bool allowNull)
        {
            return (IsValidFileName(context, filename, allowNull) &&
                    IsValidDirectoryPath(context, directorypath, allowNull) &&
                    IsValidFileContents(context, content, maxBytes, allowNull));
        }

	/**

	 */
        /// <summary>
	    /// Validates the filepath, filename, and content of a file. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException.         
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="directorypath">The directory path of the file upload.</param>
        /// <param name="filename">The name of the file to upload.</param>
        /// <param name="content">The contents of the file.</param>
        /// <param name="maxBytes">The maximum bytes allowed in the file content.</param>        
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <seealso cref="IValidator.AssertValidFileUpload(string, string, string, byte[], int, bool)">
        /// </seealso>
        public void AssertValidFileUpload(String context, String directorypath, String filename, byte[] content, int maxBytes, bool allowNull)
        {
            GetValidFileName(context, filename, allowNull);
            GetValidDirectoryPath(context, directorypath, allowNull);
            GetValidFileContents(context, content, maxBytes, allowNull);
        }

        /// <summary>
	    /// Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	    /// characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 	     
	    /// Uses current HTTPRequest saved in EASPI Authenticator
        /// </summary>        
        /// <returns>Boolean value indicating whether the request is valid</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidHttpRequest(IHttpRequest)">
        /// </seealso>
        public bool IsValidHttpRequest()
        {
            try
            {
                AssertValidHttpRequest();
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
	    /// Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
    	/// characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="request">The IHttpRequest object to validate.</param>                
        /// <returns>Boolean value indicating whether the request is valid</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidHttpRequest(IHttpRequest)">
        /// </seealso>
        public bool IsValidHttpRequest(IHttpRequest request)
        {
            try
            {
                AssertIsValidHttpRequest(request);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
  
        /// <summary>
        /// Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
        /// characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        /// will generate a descriptive IntrusionException. 
        /// 
        /// Uses current HTTPRequest saved in EASPI Authenticator
        /// </summary>
        ///                
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.AssertValidHttpRequest()">
        /// </seealso>
        public void AssertValidHttpRequest()
        {
            IHttpRequest request = ((Authenticator)Esapi.Authenticator()).Context.Request;
            AssertIsValidHttpRequest(request);
        }

        /// <summary>
        /// Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
        /// characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="request">The IHttpRequest object to validate.</param>                
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.AssertIsValidHttpRequest(IHttpRequest)">
        /// </seealso>
        public void AssertIsValidHttpRequest(IHttpRequest request)
        {
            if (request == null)
            {
                throw new ValidationException("Invalid HTTPRequest", "HTTPRequest is null");
            }

            ArrayList parameterNames = new ArrayList();
            parameterNames.AddRange(new ArrayList(request.Form.AllKeys));
            parameterNames.AddRange(new ArrayList(request.QueryString.AllKeys));
            IEnumerator i1 = parameterNames.GetEnumerator();
            while (i1.MoveNext())
            {
                String name = (String)i1.Current;
                GetValidInput("http", "HTTPParameterName", name, MAX_PARAMETER_NAME_LENGTH, false);
                String paramValue = request.Params[name];
                GetValidInput(name, "HTTPParameterValue", paramValue, MAX_PARAMETER_VALUE_LENGTH, true);
            }

            if (request.Cookies != null)
            {
                foreach (String name in request.Cookies)
                {
                    string cookieValue = request.Cookies[name].Value;
                    GetValidInput("http", "HTTPCookieName", name, MAX_PARAMETER_NAME_LENGTH, true);
                    GetValidInput(name, "HTTPCookieValue", cookieValue, MAX_PARAMETER_VALUE_LENGTH, true);
                }
            }

            IEnumerator e = request.Headers.GetEnumerator();
            while (e.MoveNext())
            {
                string name = (string)e.Current;
                if (name != null && !name.ToUpper().Equals("Cookie".ToUpper()))
                {
                    GetValidInput("http", "HTTPHeaderName", name, MAX_PARAMETER_NAME_LENGTH, true);
                    IEnumerator e2 = request.Headers.Keys.GetEnumerator();
                    while (e2.MoveNext())
                    {
                        string headerName = (string)e2.Current;

                        GetValidInput("http", "HTTPHeaderName", headerName, MAX_PARAMETER_NAME_LENGTH, true);
                        string headerValue = (string)request.Headers[headerName];
                        GetValidInput(name, "HTTPHeaderValue", headerValue, MAX_PARAMETER_VALUE_LENGTH, true);
                    }
                }
            }
        }
     
      
        /// <summary>
        /// Returns true if input is a valid list item.
        /// </summary>
        /// <param name="context">The context for validation.</param>
        /// <param name="list">The list to validate against.</param>
        /// <param name="input">The value to validate.</param>        
        /// <returns>Boolean value inidicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidListItem(string, string, IList)">
        /// </seealso>
        public bool IsValidListItem(String context, String input, IList list)
        {
            try
            {
                GetValidListItem(context, input, list);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
	    /// Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The context for validation.</param>
        /// <param name="list">The list to validate against.</param>
        /// <param name="input">The value to validate.</param>        
        /// <returns>String value, if the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidListItem(string, string, IList)">
        /// </seealso>
        public String GetValidListItem(String context, String input, IList list)
        {
            if (list.Contains(input)) return input;
            throw new ValidationException(context + " does not exist in list", "Item (" + input + ") does not exist in List " + context);
        }
        
        
        	/*
	 * 
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidParameterSet(java.util.Set,
	 *      java.util.Set, java.util.Set)
	 */

        /// <summary>
        /// Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.
        /// </summary>
        /// <param name="context">The context to perform data validation.</param>        
        /// <param name="required">The list of names that are required to exist.</param>
        /// <param name="optional">The list of names that may or may not exist.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="IValidator.IsValidHttpRequestParameterSet(string, IList, IList)">
        /// </seealso>
        public bool IsValidHttpRequestParameterSet(String context, IList required, IList optional)
        {
            try
            {
                AssertIsValidHttpRequestParameterSet(context, required, optional);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
	    /// Validates that the parameters in the current request contain all required parameters and only optional ones in
	    /// addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException.         
        /// </summary>
        /// <param name="context">The context to perform data validation.</param>        
        /// <param name="required">The list of names that are required to exist.</param>
        /// <param name="optional">The list of names that may or may not exist.</param>        
        /// <seealso cref="IValidator.AssertIsValidHttpRequestParameterSet(string, IList, IList)">
        /// </seealso>
        public void AssertIsValidHttpRequestParameterSet(String context, IList required, IList optional)
        {
            IHttpRequest request = ((Authenticator)Esapi.Authenticator()).Context.Request;
            ArrayList actualNames = new ArrayList(request.Params.Keys);

            // verify ALL required parameters are present            
            ArrayList missing = (ArrayList) ((ArrayList) required).Clone();
            IEnumerator i = actualNames.GetEnumerator();
            while (i.MoveNext())
            {
                missing.Remove(i.Current);
            }

            if (missing.Count > 0)
            {
                //TODO - we need to know WHICH element is missing
                throw new ValidationException(context + " is an invalid parameter set", "Required element missing");
            }

            // verify ONLY optional + required parameters are present            
            ArrayList extra = (ArrayList)actualNames.Clone();
            IEnumerator iRequired = required.GetEnumerator();
            while (iRequired.MoveNext())
            {
                extra.Remove(iRequired.Current);
            }
            IEnumerator iOptional = optional.GetEnumerator();
            while (iOptional.MoveNext())
            {
                extra.Remove(iOptional.Current);
            }

            if (extra.Count > 0)
            {
                throw new ValidationException(context + " is an invalid parameter set", "Parameters other than optional + required parameters are present");
            }
        }     
     
        /// <summary> 
        /// Checks that all bytes are valid ASCII characters (between 33 and 126
	    /// inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII. 
        /// </summary>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="input">The data to validate.</param>        
        /// <param name="maxLength">The maximum length of the input.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Boolean value indicating whether data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidPrintable(string, byte[], int, bool)">
        /// </seealso>
        public bool IsValidPrintable(String context, byte[] input, int maxLength, bool allowNull)
        {
            try
            {
                GetValidPrintable(context, input, maxLength, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
	
        /// <summary> 
        /// Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="input">The data to validate.</param>        
        /// <param name="maxLength">The maximum length of the input.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Byte array, if data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidPrintable(string, byte[], int, bool)">
        /// </seealso>
        public byte[] GetValidPrintable(String context, byte[] input, int maxLength, bool allowNull)
        {
            if (IsEmpty(input))
            {
                if (allowNull) return null;
                throw new ValidationException(context + " is required", "Input is required");
            }

            if (input.Length > maxLength)
            {
                throw new ValidationException(context + " can not exceed " + maxLength + " bytes", "Invalid Input. Input exceeded maxLength");
            }

            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] < 33 || input[i] > 126)
                {
                    throw new ValidationException(context + " is invalid", "Invalid Input. Some characters are not ASCII.");
                }
            }
            return input;
        }
        
        /// <summary> 
        /// Returns true if input is valid printable ASCII characters (32-126).
        /// </summary>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="input">The data to validate.</param>        
        /// <param name="maxLength">The maximum length of the input.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Boolean indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidPrintable(string, string, int, bool)">
        /// </seealso>
        public bool IsValidPrintable(String context, String input, int maxLength, bool allowNull)
        {
            try
            {
                GetValidPrintable(context, input, maxLength, allowNull);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
	
        /// <summary> 
    	/// Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException.
        /// </summary>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="input">The data to validate.</param>        
        /// <param name="maxLength">The maximum length of the input.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Byte array, if data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidPrintable(string, string, int, bool)">
        /// </seealso>
        public String GetValidPrintable(String context, String input, int maxLength, bool allowNull)
        {
            String canonical = "";
            try
            {
                canonical = Esapi.Encoder().Canonicalize(input);
                System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                GetValidPrintable(context, encoding.GetBytes(canonical), maxLength, allowNull);
            }
            catch (EncodingException ee)
            {
                logger.Error(LogEventTypes.SECURITY, "Could not canonicalize user input", ee);
            }
            return canonical;
        }

        /// <summary>
        ///   Returns true if input is a valid redirect location.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The redirect location to validate.</param>
        /// <param name="allowNull">Whether or not to allow null data.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidRedirectLocation(string, string, bool)">        
        /// </seealso>
        public bool IsValidRedirectLocation(String context, String input, bool allowNull)
        {
            // FIXME: ENHANCE - it's too hard to put valid locations in as regex
            // FIXME: ENHANCE - configurable redirect length
            return Esapi.Validator().IsValidInput(context, "Redirect", input, 512, allowNull);
        }

        /// <summary>
        /// Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive 
        /// ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The redirect location to validate.</param>
        /// <param name="allowNull">Whether or not to allow null data.</param>
        /// <returns>Valid string value, if data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.GetValidRedirectLocation(string, string, bool)">
        /// </seealso>
        public String GetValidRedirectLocation(String context, String input, bool allowNull)
        {
            // FIXME: ENHANCE - it's too hard to put valid locations in as regex
            return Esapi.Validator().GetValidInput(context, "Redirect", input, 512, allowNull);
        }
        

        /// <summary>
        ///   Implementation of IsValidSafeHTML. Should be updated to use Anti-SAMY
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="maxLength">The maximum length of the string</param>        
        /// <param name="allowNull">Whether or not null values are considered valid.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        /// <seealso cref="Owasp.Esapi.Interfaces.IValidator.IsValidSafeHtml(string, string, int ,bool)">        
        /// </seealso>
        public bool IsValidSafeHtml(string context, string input, int maxLength, bool allowNull)
        {
            try
            {
                Esapi.Validator().GetValidSafeHtml(context, input, maxLength, allowNull);
                return true;
            }
            catch (EncodingException ee)
            {
                return false;
            }
        }
        
        /// <summary>
        ///   Implementation of GetValidSafeHtml. Not implemented.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="maxLength">The maximum length of the string</param>        
        /// <param name="allowNull">Whether or not null values are considered valid.</param>        
        /// <returns>String value with safe HTML based on input.</returns>        
        public string GetValidSafeHtml(string context, string input, int maxLength, bool allowNull)
        {            
            try {
                CleanResults test = antiSamy.scan(input, policy);
                return(test.getCleanHTML().Trim());
            } catch (ScanException e) {
                throw new ValidationException( "Invalid HTML", "Problem parsing HTML (" + context + "=" + input + ") ",e );
            } catch (PolicyException e) {
                throw new ValidationException( "Invalid HTML", "HTML violates policy (" + context + "=" + input + ") ",e );
            }
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
        /// Helper function to check if a string is empty.
        /// </summary>
        /// <param name="input">Input value</param>
        /// <returns>Boolean value inidicating whether or not data is valid</returns>
        private static bool IsEmpty(String input)
        {
            return (input == null || input.Trim().Length == 0);
        }

        /// <summary>
        /// Helper function to check if a byte array is empty.
        /// </summary>
        /// <param name="input">Input value</param>
        /// <returns>Boolean value inidicating whether or not data is valid</returns>
        private static bool IsEmpty(byte[] input)
        {
            return (input == null || input.Length == 0);
        }
        
        /// <summary>
        ///   Static constructor
        /// </summary>
        static Validator()
        {
            logger = Esapi.Logger();
        }


    }
}
