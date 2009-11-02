using System.Collections.Generic;

namespace Owasp.Esapi.Runtime
{
    /// <summary>
    /// Object repository
    /// </summary>
    public interface IObjectRepository<TId, TObject>
        where TObject : class
    {
        /// <summary>
        /// Add object
        /// </summary>
        /// <param id="id">Object id</param>
        /// <param id="value">Object value</param>
        /// <returns></returns>
        IObjectRepository<TId, TObject> Register(TId id, TObject value);
        /// <summary>
        /// Remove object
        /// </summary>
        /// <param id="id"></param>
        /// <returns></returns>
        IObjectRepository<TId, TObject> Revoke(TId id);
        /// <summary>
        /// Lookup object
        /// </summary>
        /// <param id="id"></param>
        /// <param id="?"></param>
        /// <returns></returns>
        bool Lookup(TId id, out TObject value);
        /// <summary>
        /// Get object count
        /// </summary>
        int Count { get; }
        /// <summary>
        /// Get ids
        /// </summary>
        ICollection<TId> Ids { get; }
        /// <summary>
        /// Get objects
        /// </summary>
        ICollection<TObject> Objects { get; }
        /// <summary>
        /// Get object
        /// </summary>
        /// <param id="id"></param>
        /// <returns></returns>
        TObject this[TId id] { get; }
    }
}
