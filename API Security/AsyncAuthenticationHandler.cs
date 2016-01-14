using SAPIA.Model;
using SAPIA.Model.Cryptography;
using System;
using System.Net;
using System.Runtime.Caching;
using System.Security;
using System.Threading;
using System.Web;

namespace SAPIA
{
    /// <summary>
    /// Use this handler to authenticate all API requests before it hits that application logic.
    /// In order to enable this feature, the hosting web server should support only Anonymous Authentication.
    /// The rest of the authentication methods should be disabled. 
    /// </summary>
    public class AsyncAuthenticationHandler : IHttpAsyncHandler
    {

        private const string RESPONSE_CACHE_NAME = "ResponseCache";

        public static SuccesfulResponseCache cache = new SuccesfulResponseCache(RESPONSE_CACHE_NAME);

        public IAsyncResult BeginProcessRequest(HttpContext context, AsyncCallback cb, object extraData)
        {
            AsynchAuthenticationOperation asyncAuth = new AsynchAuthenticationOperation(cb, context, extraData, cache);
            asyncAuth.StartAsyncWork();
            return asyncAuth;
        }

        public void EndProcessRequest(IAsyncResult result)
        {

        }

        public bool IsReusable
        {
            get { return false; }
        }

        public void ProcessRequest(HttpContext context)
        {
            throw new NotImplementedException();
        }
    }

    class AsynchAuthenticationOperation : IAsyncResult
    {
        private const string AUTHORIZATION_TYPE = "API";

        private bool _completed;
        private Object _state;
        private AsyncCallback _callback;
        private HttpContext _context;
        private SuccesfulResponseCache _memoryCache;

        bool IAsyncResult.IsCompleted { get { return _completed; } }
        WaitHandle IAsyncResult.AsyncWaitHandle { get { return null; } }
        Object IAsyncResult.AsyncState { get { return _state; } }
        bool IAsyncResult.CompletedSynchronously { get { return false; } }

        public AsynchAuthenticationOperation(AsyncCallback callback, HttpContext context, Object state, SuccesfulResponseCache cache)
        {
            _callback = callback;
            _context = context;
            _state = state;
            _completed = false;
            _memoryCache = cache;
        }

        public void StartAsyncWork()
        {
            ThreadPool.QueueUserWorkItem(new WaitCallback(StartAsyncTask), null);
        }

        private void StartAsyncTask(Object workItemState)
        {

            var authorizationHeader = _context.Request.Headers[HttpRequestHeader.Authorization.ToString()];
            if (authorizationHeader != null)
            {
                try
                {
                    var authorizationType = authorizationHeader.Split(' ')[0];
                    if (authorizationType.Equals(AUTHORIZATION_TYPE))
                    {
                        var authenticationData = new AuthenticationData(_context);
                        var authenticator = GetAuthenticator(authenticationData);
                        var responseToCache = authenticator.AuthenticateMessage(authenticationData);
                        _memoryCache.Set(authenticationData.SharedKey, responseToCache, null);
                    }
                }
                catch (SecurityException securityEx)
                {
                    _context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    _context.Response.StatusDescription = securityEx.Message;
                }
                catch (TimeoutException timeOutEx)
                {
                    _context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    _context.Response.SubStatusCode = (int)HttpStatusCode.RequestTimeout;
                    _context.Response.StatusDescription = timeOutEx.Message;
                }
                catch (Exception)
                {
                    _context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    _context.Response.SubStatusCode = (int)HttpStatusCode.InternalServerError;
                }
            }
            else
            {
                _context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            }
            _completed = true;
            _callback(this);
        }

        private IMessageAuthenticationCodeVerifier GetAuthenticator(AuthenticationData authenticationData)
        {
            IMessageAuthenticationCodeVerifier authenticator;
            SuccessfulResponse cashedResponseData;
            if (_memoryCache.TryGet(authenticationData.SharedKey, out cashedResponseData))
                authenticator = new HMACAuthenticator(cashedResponseData.SecretKey);
            else
                authenticator = new HMACAuthenticator(authenticationData);
            return authenticator;
        }
    }
}
