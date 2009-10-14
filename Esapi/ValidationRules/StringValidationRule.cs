using System;
using System.Collections.Generic;
using System.Text;
using Owasp.Esapi.Interfaces;
using System.Text.RegularExpressions;
using EM = Owasp.Esapi.Resources.Errors;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi.ValidationRules
{
    [ValidationRule(BuiltinValidationRules.String, AutoLoad = false)]
    public class StringValidationRule : IValidationRule
    {
        private List<Regex> _whitelist;
        private List<Regex> _blacklist;

        bool _allowNullOrEmpty = false;

        private int _minLength = 0;
        private int _maxLength = int.MaxValue;

        /// <summary>
        /// Initialize string validation rule
        /// </summary>
        public StringValidationRule()
        {
            _whitelist = new List<Regex>();
            _blacklist = new List<Regex>();
        }

        /// <summary>
        /// Add pattern to whitelist
        /// </summary>
        /// <param name="pattern">String pattern</param>
        public void AddWhitelistPattern(string pattern)
        {
            try {
                _whitelist.Add(new Regex(pattern));
            }
            catch (Exception exp) {
                throw new ArgumentException(EM.InvalidArgument, exp);
            }
        }

        /// <summary>
        /// Allow null or empty values
        /// </summary>
        public bool AllowNullOrEmpty
        {
            get { return _allowNullOrEmpty;  }
            set { _allowNullOrEmpty = value; }
        }

        /// <summary>
        /// Add pattern to blacklist
        /// </summary>
        /// <param name="pattern">String pattern</param>
        public void AddBlacklistPattern(string pattern)
        {
            try {
                _blacklist.Add(new Regex(pattern));
            }
            catch (Exception exp) {
                throw new ArgumentException(EM.InvalidArgument, exp);
            }
        }

        /// <summary>
        ///  Minimum length value
        /// </summary>
        public int MinLength
        {
            get { return _minLength; }
            set
            {
                if (value < 0) {
                    throw new ArgumentException(EM.InvalidArgument);
                }
                _minLength = value;
            }
        }

        /// <summary>
        /// Maximum length value
        /// </summary>
        public int MaxLength
        {
            get { return _maxLength;  } 
            set { _maxLength = value;  }
        }

        #region IValidationRule Members

        /// <summary>
        /// Validate string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public bool IsValid(string input)
        {
            if (string.IsNullOrEmpty(input)) {
                return _allowNullOrEmpty;
            }

            // Check length
            if (input.Length < _minLength || input.Length > _maxLength) {
                return false;
            }

            // Check whitelist patterns
            foreach (Regex r in _whitelist) {
                if (!r.IsMatch(input)) {
                    return false;
                }
            }

            // Check blacklist patterns
            foreach (Regex r in _blacklist) {
                if (r.IsMatch(input)) {
                    return false;
                }
            }

            return true;
        }

        #endregion
    }
}
