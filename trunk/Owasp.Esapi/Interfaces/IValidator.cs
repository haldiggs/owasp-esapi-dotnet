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
/// <author>  Alex Smolen [a href="http://www.foundstone.com"]Foundstone[/a]
/// </author>
/// <created>  2008 </created>

using System;
using System.Web;
using System.Collections;
using System.IO;
using HttpInterfaces;
using System.Globalization;

namespace Owasp.Esapi.Interfaces
{

    /// <summary> The IValidator interface defines a set of methods for canonicalizing and
    /// validating untrusted input. Implementors should feel free to extend this
    /// interface to accomodate their own data formats. Rather than throw exceptions,
    /// this interface returns boolean results because not all validation problems
    /// are security issues. Boolean returns allow developers to handle both valid
    /// and invalid results more cleanly than exceptions.
    /// [P]
    /// [img src="doc-files/Validator.jpg" height="600"]
    /// [P]
    /// Implementations must adopt a "whitelist" approach to validation where a
    /// specific pattern or character set is matched. "Blacklist" approaches that
    /// attempt to identify the invalid or disallowed characters are much more likely
    /// to allow a bypass with encoding or other tricks.
    /// 
    /// </summary>
    /// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <created>  2008 </created>
    
    public interface IValidator
    {

        /// <summary>         
        /// Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="type">The type of data to validate.</param>
        /// <param name="data">The data to validate.</param>
        /// <param name="maxLength">The maximum valid length.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>Boolean value indicating whether or not the data is valid.</returns>
        bool IsValidInput(string context, String type, String data, int maxLength, bool allowNull);
        
        /// <summary> 
        /// Returns true if input is valid according to the specified type. Types are referenced by name against the ESAPI configuration. Implementers
	    /// should take care to make the type storage simple to understand and configure.
        /// </summary>                        
        /// <param name="context">The validation context.</param>
        /// <param name="type">The type of data to validate.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="maxLength">The maximum valid length.</param>
        /// <param name="allowNull">Whether or not null values are valid.</param>
        /// <returns>The canonicalized input.</returns> 
        string GetValidInput(string context, string type, string input, int maxLength, bool allowNull);
        
        /// <summary>
        ///   Returns true if input is a valid date according to the specified date format.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="format">The DateTimeFormat object to use.</param>        
        /// <param name="allowNull">Specifies whether or not null values are valid</param>
        /// <returns>True if date is valid.</returns>
        Boolean IsValidDate(string context, string input, DateTimeFormatInfo format, Boolean allowNull);
        
        /// <summary>
        ///    Checks whether date is valid.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="format">The DateTimeFormat object to use.</param>        
        /// <param name="allowNull">Specifies whether or not null values are valid</param>
        /// <returns>DateTime object with value of date.</returns>
        DateTime GetValidDate(string context, string input, DateTimeFormatInfo format, Boolean allowNull);

        /// <summary>
        /// Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="data">The data to validate.</param>        
        /// <param name="allowNull">Specifies whether or not to allow null</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidCreditCard(string context, string data, Boolean allowNull);

        /// <summary>
        /// Returns a canonicalized and validated credit card number as a String. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>        
        /// <param name="allowNull">Specifies whether or not to allow null</param>
        /// <returns>The credit card number if it is valid.</returns>
        String GetValidCreditCard(string context, string input, Boolean allowNull);        
        
        /// <summary> 
        /// Returns true if input is a valid directory path.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="dirpath">The directory to validate.</param>        
        /// <param name="allowNull">Specifies whether or not to allow null</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidDirectoryPath(string context, string dirpath, Boolean allowNull);

        /// <summary> 
        /// Returns a canonicalized and validated directory path as a String. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
	    /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="dirpath">The directory to validate.</param>        
        /// <param name="allowNull">Specifies whether or not to allow null</param>
        /// <returns>Directory path, if data is valid.</returns>
        String GetValidDirectoryPath(string context, string dirpath, Boolean allowNull);        
        
        /// <summary> 
        /// Returns true if input is a valid double.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The directory to validate.</param>        
        /// <param name="maxValue">The maximum valid value</param>
        /// <param name="minValue">The minimum valid value</param>
        /// <param name="allowNull">Specifies whether or not to allow null</param>
        /// <returns> true, if data is valid.</returns>
        Boolean IsValidDouble(String context, String input, double minValue, double maxValue, Boolean allowNull);

        /// <summary> 
        /// Returns a validated real number as a double. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The directory to validate.</param>        
        /// <param name="maxValue">The maximum valid value</param>
        /// <param name="minValue">The minimum valid value</param>
        /// <param name="allowNull">Specifies whether or not to allow null</param>
        /// <returns>Double, if data is valid.</returns>
        Double GetValidDouble(String context, String input, double minValue, double maxValue, Boolean allowNull);

        /// <summary> 
        /// Returns true if input is valid file content.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The file content to validate.</param>        
        /// <param name="allowNull">Whether or not null values are valid</param>
        /// <param name="maxBytes">The maximum number of bytes in the file</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>           
        Boolean IsValidFileContents(String context, byte[] input, int maxBytes, Boolean allowNull);

	    /// <summary> 
        /// Returns validated file content as a byte array. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The file content to validate.</param>        
        /// <param name="allowNull">Whether or not null values are valid</param>
        /// <param name="maxBytes">The maximum number of bytes in the file</param>
        /// <returns>File contents as byte array if data is valid.</returns>           
        byte[] GetValidFileContents(String context, byte[] input, int maxBytes, Boolean allowNull);             
       
	    /// <summary> 
        /// Returns true if input is a valid file name.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The filename to validate.</param>
        /// <param name="allowNull">Whether or not to treat null values as valid</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        Boolean IsValidFileName(String context, String input, Boolean allowNull);

	    /// <summary> 
        /// Returns a canonicalized and validated file name as a String. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
	     /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The filename to validate.</param>
        /// <param name="allowNull">Whether or not to treat null values as valid</param>
        /// <returns>File name, if the data is valid.</returns>
        String GetValidFileName(String context, String input, Boolean allowNull);		
        
        /// <summary> 
        /// Checks whether a file upload has a valid name, path, and content. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="filepath">The file path.</param>
        /// <param name="filename">The file name.</param>
        /// <param name="content">The contents of the file.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>        
        bool IsValidFileUpload(string context, string filepath, string filename, byte[] content, int maxBytes, Boolean allowNull);
       	
	            
        /// <summary> 
        /// Validates the filepath, filename, and content of a file. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="filepath">The file path.</param>
        /// <param name="filename">The file name.</param>
        /// <param name="content">The contents of the file.</param>        
	    void AssertValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, Boolean allowNull);


        /// <summary> Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
        /// characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.        
        /// </summary>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidHttpRequest();
        
        /// <summary> Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
        /// characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.        
        /// </summary>
        /// <param name="request">The IHttpRequest object to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidHttpRequest(IHttpRequest request);
       
        /// <summary> 
        /// Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	    /// characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        void AssertValidHttpRequest();     
        
        /// <summary>
        /// Returns true if input is a valid integer.
        /// </summary>
        /// <param name="allowNull">Whether or not null values are considered valid</param>
        /// <param name="context">The context for validation</param>
        /// <param name="input">The input to validate</param>
        /// <param name="maxValue">The maximum valid value</param>
        /// <param name="minValue">The minimum valid value</param>        
        /// <returns>Boolean value indicating whether the integer is valid.</returns>            
	    Boolean IsValidInteger(String context, String input, int minValue, int maxValue, Boolean allowNull);
	
        /// <summary>
	    /// Returns a validated integer as an int. Invalid input
    	/// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="allowNull">Whether or not null values are considered valid</param>
        /// <param name="context">The context for validation</param>
        /// <param name="input">The input to validate</param>
        /// <param name="maxValue">The maximum valid value</param>
        /// <param name="minValue">The minimum valid value</param>        
        /// <returns>Integer value if data is valid.</returns>            
        int GetValidInteger(String context, String input, int minValue, int maxValue, Boolean allowNull);	
                
        /// <summary> 
        /// Returns true if input is a valid list item.        
        /// </summary>
        /// <param name="list">The list to validate against.</param>
        /// <param name="listValue">The value to validate.</param>        
        /// <param name="context">The context for validation.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidListItem(String context, string listValue, IList list);

        /// <summary> 
        /// Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="list">The list to validate against.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="context">The context for validation.</param>        
        /// <returns>List item as a string, if data is valid.</returns>
    	String GetValidListItem(String context, String input, IList list);
                  
        /// <summary> 
        /// Returns true if the input is a valid number
        /// </summary>
        /// <param name="input">The data to validate.</param>        
        /// <param name="context">The context perform validation.</param>
        /// <param name="maxValue">The maximum valid value.</param>
        /// <param name="minValue">The minimum valid value.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidNumber(string context, string input, long minValue, long maxValue, Boolean allowNull);

        /// <summary> 
	    /// Returns a validated number as a double. Invalid input
	    /// will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
	     /// </summary>
        /// <param name="input">The data to validate.</param>        
        /// <param name="context">The context perform validation.</param>
        /// <param name="maxValue">The maximum valid value.</param>
        /// <param name="minValue">The minimum valid value.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        Double GetValidNumber(String context, String input, long minValue, long maxValue, Boolean allowNull);	
        
        /// <summary> 
        ///  Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.
        /// </summary>
        /// <param name="requiredNames">The list of names that are required to exist.</param>
        /// <param name="optionalNames">The list of names that may or may not exist.</param>
        /// <param name="context">The context to validate the parameter set</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidHttpRequestParameterSet(String context, IList requiredNames, IList optionalNames);

        /// Validates that the parameters in the current request contain all required parameters and only optional ones in
	    /// addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 	    
        /// <param name="requiredNames">The list of names that are required to exist.</param>
        /// <param name="optionalNames">The list of names that may or may not exist.</param>
        /// <param name="context">The context to validate the parameter set</param>
        void AssertIsValidHttpRequestParameterSet(String context, IList requiredNames, IList optionalNames);
        
        
        /// <summary> Returns true if input is valid printable ASCII characters.</summary>        
        /// <param name="input">The data to validate.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="maxLength">The maximum length of the byte array.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidPrintable(String context, byte[] input, int maxLength, Boolean allowNull);

        /// <summary>
        /// Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>        
        /// <param name="input">The data to validate.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="maxLength">The maximum length of the byte array.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
    	byte[] GetValidPrintable(String context, byte[] input, int maxLength, Boolean allowNull);

        
        /// <summary> Returns true if input is valid printable ASCII characters.</summary>
        /// <param name="input">The data to validate.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="maxLength">The maximum length of the string</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidPrintable(String context, string input, int maxLength, Boolean allowNull);

        /// <summary>
        /// Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	    /// will generate a descriptive IntrusionException. 
        /// </summary>
        /// <param name="input">The data to validate.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <param name="context">The context to perform validation.</param>
        /// <param name="maxLength">The maximum length of the string</param>        
        /// <returns>Printable String value, if the data is valid.</returns>
        String GetValidPrintable(String context, String input, int maxLength, Boolean allowNull);
        
        
        /// <summary> 
        /// Returns true if input is a valid redirect location.        
        /// </summary>        
        /// <param name="context">The validation context.</param>
        /// <param name="location">The redirect location to validate.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidRedirectLocation(string context, string location, Boolean allowNull);

        
        /// <summary> 
        /// Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        /// will generate a descriptive IntrusionException. 
	    /// </summary>        
        /// <param name="context">The validation context.</param>
        /// <param name="input">The redirect location to validate.</param>
        /// <param name="allowNull">Whether or not null values are considered valid.</param>
        /// <returns>String value of redirect location, if data is valid.</returns>
        String GetValidRedirectLocation(String context, String input, Boolean allowNull);

        
        /// <summary> 
        /// Checks if input is a valid safe HTML.        
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="maxLength">The maximum length of the string</param>        
        /// <param name="allowNull">Whether or not null values are considered valid.</param>                
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidSafeHtml(string context, string input, int maxLength, bool allowNull);


        /// <summary>
        ///    Checks if input is valid safe HTML. Throws exception is HTML is not valid.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="maxLength">The maximum length of the string</param>        
        /// <param name="allowNull">Whether or not null values are considered valid.</param>        
        /// <returns>String value with safe HTML based on input.</returns>        
        string GetValidSafeHtml(string context, string input, int maxLength, bool allowNull);
       

        /// <summary> Reads from an input stream until end-of-line or a maximum number of
        /// characters. This method protects against the inherent denial of service
        /// attack in reading until the end of a line. If an attacker doesn't ever
        /// send a newline character, then a normal input stream reader will read
        /// until all memory is exhausted and the platform throws an OutOfMemoryError
        /// and probably terminates.
        /// 
        /// </summary>
        /// <param name="inStream">The stream value to read from.</param>
        /// <param name="max">The maximum bytes to read from the stream.</param>
        /// <returns>The line read from the stream.</returns>
        string SafeReadLine(Stream inStream, int max);
        
    }
}
