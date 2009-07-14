using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owasp.Esapi.ValidationRules;

namespace Owasp.Esapi.Interfaces
{
    public interface IValidator
    {
        bool IsValid(string rule, string input);

        void AddRule(string name, IValidationRule rule);

        IValidationRule GetRule(string name);

        void RemoveRule(string name);
    }
}
