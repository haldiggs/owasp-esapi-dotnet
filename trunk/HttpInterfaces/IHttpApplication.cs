using System;
using System.Security.Principal;
using System.Web;

namespace HttpInterfaces
{  
    public interface IHttpApplication
    {
        IHttpContext Context {get;}
        
        IHttpRequest Request {get;}
        
        IHttpResponse Response {get;}
        
        IHttpSession Session {get;}
        
        IHttpApplicationState Application { get; }
        
        IHttpServerUtility Server {get;}
        
        IPrincipal User {get;}
        
        IHttpModuleCollection Modules{get;}
                
        event EventHandler BeginRequest;
        
        event EventHandler AuthenticateRequest;
        
        event EventHandler PostAuthenticateRequest;
        
        event EventHandler AuthorizeRequest;
        
        event EventHandler PostAuthorizeRequest;
        
        event EventHandler ResolveRequestCache;
        
        event EventHandler PostResolveRequestCache;
        
        event EventHandler MapRequestHandler;
        
        event EventHandler PostMapRequestHandler;
        
        event EventHandler AcquireRequestState;
        
        event EventHandler PostAcquireRequestState;
        
        event EventHandler PreRequestHandlerExecute;
        
        event EventHandler PostRequestHandlerExecute;
        
        event EventHandler ReleaseRequestState;
        
        event EventHandler PostReleaseRequestState;
        
        event EventHandler UpdateRequestCache;
        
        event EventHandler PostUpdateRequestCache;
        
        event EventHandler LogRequest;
        
        event EventHandler PostLogRequest;
        
        event EventHandler EndRequest;
        
        event EventHandler Error;
        
        event EventHandler PreSendRequestHeaders;
        
        event EventHandler PreSendRequestContent;
        
        void CompleteRequest();
        
        void AddOnBeginRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnBeginRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnAuthenticateRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnAuthenticateRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostAuthenticateRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostAuthenticateRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnAuthorizeRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnAuthorizeRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostAuthorizeRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostAuthorizeRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnResolveRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnResolveRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostResolveRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostResolveRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnMapRequestHandlerAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnMapRequestHandlerAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostMapRequestHandlerAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostMapRequestHandlerAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnAcquireRequestStateAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnAcquireRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostAcquireRequestStateAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostAcquireRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPreRequestHandlerExecuteAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPreRequestHandlerExecuteAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostRequestHandlerExecuteAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostRequestHandlerExecuteAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnReleaseRequestStateAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnReleaseRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostReleaseRequestStateAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostReleaseRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnUpdateRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnUpdateRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostUpdateRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostUpdateRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnLogRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnLogRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnPostLogRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnPostLogRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void AddOnEndRequestAsync(BeginEventHandler bh, EndEventHandler eh);
        
        void AddOnEndRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state);
        
        void Init();

		string GetVaryByCustomString(IHttpContext context, string custom);
    }
}
