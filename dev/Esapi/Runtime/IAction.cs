
namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Action interface
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
