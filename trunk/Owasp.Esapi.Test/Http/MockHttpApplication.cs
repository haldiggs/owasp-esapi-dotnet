/// <summary> OWASP .NET Enterprise Security API (.NET ESAPI) 
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// .NET Enterprise Security API (.NET ESAPI) project. For details, please see
/// http://www.owasp.org/index.php/.NET_ESAPI.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The .NET ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using System.Collections.Generic;
using System.Text;
using HttpInterfaces;

namespace Owasp.Esapi.Test.Http
{
    class MockHttpApplication: IHttpApplication
    {
        #region IHttpApplication Members

        IHttpContext context;
        IHttpRequest request;
        IHttpResponse response;
        IHttpSession session;
        
        public MockHttpApplication(MockHttpContext _context, IHttpRequest _request, IHttpResponse _response, IHttpSession _session)
        {
            context = _context;
            request = _request;
            response = _response;
            session = _session;
        }
        
        public IHttpContext Context
        {
            get { return context; }
            set { context = value;}
        }

        public IHttpRequest Request
        {
            get { return request; }
            set { request = value; }
        }

        public IHttpResponse Response
        {
            get { return response; }
            set { response = value; }
        }

        public IHttpSession Session
        {
            get { return session; }
            set { session = value; }
        }

        public IHttpApplicationState Application
        {
            get { throw new Exception("The method or operation is not implemented."); }
        }

        public IHttpServerUtility Server
        {
            get { throw new Exception("The method or operation is not implemented."); }
        }

        public System.Security.Principal.IPrincipal User
        {
            get { throw new Exception("The method or operation is not implemented."); }
        }

        public IHttpModuleCollection Modules
        {
            get { throw new Exception("The method or operation is not implemented."); }
        }

        public event EventHandler BeginRequest;

        public event EventHandler AuthenticateRequest;

        public event EventHandler PostAuthenticateRequest;

        public event EventHandler AuthorizeRequest;

        public event EventHandler PostAuthorizeRequest;

        public event EventHandler ResolveRequestCache;

        public event EventHandler PostResolveRequestCache;

        public event EventHandler MapRequestHandler;

        public event EventHandler PostMapRequestHandler;

        public event EventHandler AcquireRequestState;

        public event EventHandler PostAcquireRequestState;

        public event EventHandler PreRequestHandlerExecute;

        public event EventHandler PostRequestHandlerExecute;

        public event EventHandler ReleaseRequestState;

        public event EventHandler PostReleaseRequestState;

        public event EventHandler UpdateRequestCache;

        public event EventHandler PostUpdateRequestCache;

        public event EventHandler LogRequest;

        public event EventHandler PostLogRequest;

        public event EventHandler EndRequest;

        public event EventHandler Error;

        public event EventHandler PreSendRequestHeaders;

        public event EventHandler PreSendRequestContent;

        public void CompleteRequest()
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnBeginRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnBeginRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnAuthenticateRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnAuthenticateRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostAuthenticateRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostAuthenticateRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnAuthorizeRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnAuthorizeRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostAuthorizeRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostAuthorizeRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnResolveRequestCacheAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnResolveRequestCacheAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostResolveRequestCacheAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostResolveRequestCacheAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnMapRequestHandlerAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnMapRequestHandlerAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostMapRequestHandlerAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostMapRequestHandlerAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnAcquireRequestStateAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnAcquireRequestStateAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostAcquireRequestStateAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostAcquireRequestStateAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPreRequestHandlerExecuteAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPreRequestHandlerExecuteAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostRequestHandlerExecuteAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostRequestHandlerExecuteAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnReleaseRequestStateAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnReleaseRequestStateAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostReleaseRequestStateAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostReleaseRequestStateAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnUpdateRequestCacheAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnUpdateRequestCacheAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostUpdateRequestCacheAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostUpdateRequestCacheAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnLogRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnLogRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostLogRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnPostLogRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnEndRequestAsync(System.Web.BeginEventHandler bh, System.Web.EndEventHandler eh)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void AddOnEndRequestAsync(System.Web.BeginEventHandler beginHandler, System.Web.EndEventHandler endHandler, object state)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public void Init()
        {
            throw new Exception("The method or operation is not implemented.");
        }

        public string GetVaryByCustomString(IHttpContext context, string custom)
        {
            throw new Exception("The method or operation is not implemented.");
        }

        #endregion
    }
}
