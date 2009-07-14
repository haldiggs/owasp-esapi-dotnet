using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Owasp.Esapi.Interfaces
{
    public interface IValidationRule
    {
        bool IsValid(string input);        
    }
}
