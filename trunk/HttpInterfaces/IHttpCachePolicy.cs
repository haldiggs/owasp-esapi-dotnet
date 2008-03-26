using System;
using System.Web;
    
namespace HttpInterfaces
{
   
    public interface IHttpCachePolicy
    {
        HttpCacheVaryByContentEncodings VaryByContentEncodings
        {
            get;
        }
        
        HttpCacheVaryByHeaders VaryByHeaders
        {
            get;
        }
        
        HttpCacheVaryByParams VaryByParams
        {
            get;
        }
        
        void SetNoServerCaching();
        
        void SetVaryByCustom(string custom);
        
        void AppendCacheExtension(string extension);
        
        void SetNoTransforms();
        
        void SetCacheability(HttpCacheability cacheability);
        
        void SetCacheability(HttpCacheability cacheability, string field);
        
        void SetNoStore();
        
        void SetExpires(DateTime date);
        
        void SetMaxAge(TimeSpan delta);
        
        void SetProxyMaxAge(TimeSpan delta);
        
        void SetSlidingExpiration(bool slide);
        
        void SetValidUntilExpires(bool validUntilExpires);
        
        void SetAllowResponseInBrowserHistory(bool allow);
        
        void SetRevalidation(HttpCacheRevalidation revalidation);
        
        void SetETag(string etag);
        
        void SetLastModified(DateTime date);
        
        void SetLastModifiedFromFileDependencies();
        
        void SetETagFromFileDependencies();
        
        void SetOmitVaryStar(bool omit);
        
        void AddValidationCallback(HttpCacheValidateHandler handler, object data);
    }
}
