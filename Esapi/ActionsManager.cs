using System.Collections.Generic;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi
{
    public class AddinManager<TAddin> : IAddinManager<TAddin>
        where TAddin : class
    {
        private Dictionary<string, TAddin> _addins;

        public AddinManager()
        {
            _addins = new Dictionary<string, TAddin>();
        }

        #region IAddinManager<TAddin>
        public virtual void Add(string name, TAddin addin)
        {
            _addins.Add(name, addin);
        }

        public virtual void Clear()
        {
            _addins.Clear();
        }

        public virtual bool Contains(string name)
        {
            return _addins.ContainsKey(name);
        }

        public virtual bool Remove(string name)
        {
            return _addins.Remove(name);
        }

        public virtual bool TryGetAddin(string name, out TAddin addin)
        {
            return _addins.TryGetValue(name, out addin);
        }
        #endregion
    }

    public class ActionsManager : AddinManager<IAction>
    {
        
    }

    public class RulesManager : AddinManager<IRule>
    {
    }

    public class ConditionsManager : AddinManager<ICondition>
    {
    }
}
