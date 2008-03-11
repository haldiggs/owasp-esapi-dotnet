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
        /// Validates data received from the browser and returns a safe version.
        /// </summary>                        
        /// <param name="context">The validation context.</param>
        /// <param name="type">The type of data to validate.</param>
        /// <param name="input">The data to validate.</param>
        /// <returns>The canonicalized input.</returns> 
        string GetValidDataFromBrowser(string context, string type, string input);


        /// <summary>
        ///    Checks whether date is valid.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <param name="format">The DateTimeFormat object to use.</param>        
        /// <returns>DateTime object with value of date.</returns>
        DateTime GetValidDate(string context, string input, DateTimeFormatInfo format);

        /// <summary>
        ///   Checks wheter credit card is valid.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="data">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidCreditCard(string context, string data);

        /// <summary> 
        /// Checks if input is a valid directory path.        
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="dirpath">The directory to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidDirectoryPath(string context, string dirpath);

        /// <summary> 
        /// Checks if input is a valid file upload.        
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="content">The file content to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>   
        bool IsValidFileContent(string context, byte[] content);

        /// <summary> 
        /// Checks if input is a valid file name.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The filename to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidFileName(string context, string input);

        /// <summary> 
        /// Checks whether a file upload has a valid name, path, and content. 
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="filepath">The file path.</param>
        /// <param name="filename">The file name.</param>
        /// <param name="content">The contents of the file.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>        
        bool IsValidFileUpload(string context, string filepath, string filename, byte[] content);

        /// <summary> Validate an HTTP requests by comparing parameters, headers, and cookies to a predefined whitelist of allowed
        /// characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.        
        /// </summary>
        /// <param name="request">The IHttpRequest object to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidHttpRequest(IHttpRequest request);

        /// <summary> 
        /// Checks if input is a valid list item.        
        /// </summary>
        /// <param name="list">The list to validate against.</param>
        /// <param name="listValue">The value to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidListItem(IList list, string listValue);

        /// <summary> 
        /// Checks whether the input is a valid number
        /// </summary>
        /// <param name="input">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidNumber(string input);

        /// <summary> 
        /// Checks if is valid parameter set. // no extra, no missing        
        /// </summary>
        /// <param name="requiredNames">The list of names that are required to exist.</param>
        /// <param name="optionalNames">The list of names that may or may not exist.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidParameterSet(ArrayList requiredNames, ArrayList optionalNames);

        /// <summary> Checks if input is valid printable ASCII characters.</summary>        
        /// <param name="input">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidPrintable(byte[] input);

        /// <summary> Checks if input is valid printable ASCII characters.</summary>
        /// <param name="input">The data to validate.</param>        
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidPrintable(string input);

        /// <summary> 
        /// Checks if input is a valid redirect location.        
        /// </summary>        
        /// <param name="context">The validation context.</param>
        /// <param name="location">The redirect location to validate.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidRedirectLocation(string context, string location);

        /// <summary> 
        /// Checks if input is a valid safe HTML.        
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="input">The data to validate.</param>
        /// <returns>Boolean value indicating whether the data is valid.</returns>
        bool IsValidSafeHtml(string context, string input);


        /// <summary> 
        /// Returns true if data received from browser is valid.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <param name="type">The type of data to validate.</param>
        /// <param name="data">The data to validate.</param>
        /// <returns>Boolean value indicating whether or not the data is valid.</returns>
        bool IsValidDataFromBrowser(string context, String type, String data);

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
