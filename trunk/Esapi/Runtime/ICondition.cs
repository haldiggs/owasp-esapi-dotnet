
namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Condition interface
    /// </summary>
    /// <remarks>Used to test a runtime stage</remarks>
    public interface ICondition
    {
        /// <summary>
        /// Evaluate condition
        /// </summary>
        /// <param name="args">Condition arguments</param>
        /// <returns>True if condition valid, false otherwise</returns>
        bool Evaluate(ConditionArgs args);
    }
}
