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
using System.IO;
using System.Text.RegularExpressions;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi
{
    /// <summary> 
    /// This class is used to safely access files. Rather than extending FileInfo, this class keeps
    /// a private instance of a FileInfo class which can be accessed by callers through a public
    /// property. The difference from the Java implemenation has to do with the fact the FileInfo is
    /// sealed.
    /// </summary>
    /// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
    /// </author>
    /// <since> April 23, 2008
    /// </since>
    public class SafeFile
    {
        private static readonly long serialVersionUID = 1L;
        readonly String dirBlackList = "([*?<>|])";
        readonly String fileBlackList = "([\\\\/:*?<>|])";
        readonly String percents = "(%)([0-9a-fA-F])([0-9a-fA-F])";
        
        private FileInfo safeFileInfo;
        /// <summary>
        /// SafeFile constructor takes path as parameter
        /// </summary>
        /// <param name="path">Path to file</param>
        public SafeFile(String path)
        {
            try
            {
                safeFileInfo = new FileInfo(path);
            } catch (ArgumentException ex)
            {
                throw new ValidationException("File path was invalid.", "File path caused ArgumentException", ex);
            }
            DoDirCheck(safeFileInfo.DirectoryName);
            DoFileCheck(safeFileInfo.Name);            
        }
                
        /// <summary>
        /// Constructor for SafeFile which takes URI as parameter
        /// </summary>
        /// <param name="uri">URI to file</param>
        public SafeFile(Uri uri)
        {
            safeFileInfo = new FileInfo(new Uri(uri.ToString()).LocalPath);
            DoDirCheck(safeFileInfo.DirectoryName);
            DoFileCheck(safeFileInfo.Name);
            
        }
     
        
        //  FIXME: much stricter file validation using Validator - but won't work as drop-in replacement as well
        //private void DoFileCheck( String path ) 
        //{
        //    if ( !Esapi.Validator().IsValidFileName( "SafeFile constructor", path ) ) 
        //    {
        //        throw new ValidationException("Invalid file", "File path (" + path + ") is invalid" );
        //    }
        //}      	
               
        private void DoDirCheck(String path)
        {
            string matches = GetMatches(path, dirBlackList);
            if (matches != null)
            {
                throw new ValidationException( "Invalid directory", "Directory path (" + path + ") contains illegal character: " + matches );
            }
            matches = GetMatches(path, percents);
            if (matches != null)
            {
                throw new ValidationException("Invalid directory", "Directory path (" + path + ") contains encoded characters: " + matches);
            }
            int ch = ContainsUnprintableCharacters(path);
            if (ch != -1) 
            {
                throw new ValidationException("Invalid directory", "Directory path (" + path + ") contains unprintable character: " + ch);
            }
        }


        private void DoFileCheck(String path)
        {
            string matches = GetMatches(path, fileBlackList);
            if (matches != null)
            {
                throw new ValidationException("Invalid file", "File path (" + path + ") contains illegal character: " + matches);
            }
            matches = GetMatches(path, percents);
            if (matches != null)
            {
                throw new ValidationException("Invalid file", "File path (" + path + ") contains encoded characters: " + matches);
            }

            int ch = ContainsUnprintableCharacters(path);
            if (ch != -1)
            {
                throw new ValidationException("Invalid file", "File path (" + path + ") contains unprintable character: " + ch);
            }
        }

        private int ContainsUnprintableCharacters(String s)
        {
            // FIXME: use Validator.isValidPrintable( s );
            char[] charArray = s.ToCharArray();
            for (int i = 0; i < s.Length; i++)
            {
                char ch = charArray[i];
                if (((int)ch) < 32 || ((int)ch) > 126)
                {
                    return (int)ch;
                }
            }
            return -1;
        }

        private string GetMatches(string text, string regex)
        {
            MatchCollection matches = Regex.Matches(text, regex);
            if (matches.Count != 0)
            {
                String matchesOutputString = "";
                foreach (Match m in matches)
                {
                    foreach (Group g in m.Groups)
                    {
                        matchesOutputString += ((matchesOutputString.Length == 0) ? g.ToString() : ", " + g.ToString());
                    }
                }
                return matchesOutputString;
            }
            return null;
        }
    
        /// <summary>
        /// Returns the FileInfo for the SafeFile
        /// </summary>
        public FileInfo SafeFileInfo
        {
            get
            {
                return safeFileInfo;
            }
        }
    }
}


