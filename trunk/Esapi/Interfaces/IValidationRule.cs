
namespace Owasp.Esapi.Interfaces
{
    public interface IValidationRule
    {
        bool IsValid(string input);        
    }
}
