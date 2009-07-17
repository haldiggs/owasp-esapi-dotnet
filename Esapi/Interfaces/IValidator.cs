
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
