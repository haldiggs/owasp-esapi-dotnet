using System;
using System.Web.Caching;

namespace HttpInterfaces
{
    public interface ICache
    {
        int Count { get; }
        
        long EffectivePrivateBytesLimit { get; }
        
        long EffectivePercentagePhysicalMemoryLimit { get; }
        
        object Get(string key);
        
        void Insert(string key, object value);
        
        void Insert(string key, object value, CacheDependency dependencies);
        
        void Insert(string key, object value, CacheDependency dependencies, DateTime absoluteExpiration, TimeSpan slidingExpiration);
        
        void Insert(string key, object value, CacheDependency dependencies, DateTime absoluteExpiration, TimeSpan slidingExpiration, CacheItemPriority priority, CacheItemRemovedCallback onRemoveCallback);
        
        object Add(string key, object value, CacheDependency dependencies, DateTime absoluteExpiration, TimeSpan slidingExpiration, CacheItemPriority priority, CacheItemRemovedCallback onRemoveCallback);
        
        object Remove(string key);
    }
}
