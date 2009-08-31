
namespace Owasp.Esapi.Interfaces
{
    /// <summary>
    /// The IAction interface defines as actionable item
    /// </summary>
    public interface IAction
    {
        /// <summary>
        /// Execute action
        /// </summary>
        /// <param name="args">Action arguments</param>
        void Execute(ActionArgs args);
    }
}
