using SAPIA_NET_Server_SDK.Model;
using SAPIA_NET_Server_SDK.Model.Cryptography;
using System;
using System.Collections.Specialized;
using System.Net;
using System.Security;
using System.Security.Principal;
using System.Web;

namespace SAPIA_NET_Server_SDK
{
    public class AuthenticationModule : IHttpModule
    {

        private const string RESPONSE_CACHE_NAME = "ResponseCache";
        internal static SuccesfulResponseCache _cache = new SuccesfulResponseCache(RESPONSE_CACHE_NAME);
        private const string AUTHORIZATION_TYPE = "API";

        public void Dispose()
        {
            //clean-up code here.
        }

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += (new EventHandler(this.Context_AuthenticateRequest));
        }

        void Context_AuthenticateRequest(object sender, EventArgs e)
        {
            var app = sender as HttpApplication;
            var requestHeaders = app.Context.Request.Headers;
            var authorizationHeader = requestHeaders[HttpRequestHeader.Authorization.ToString()];
            if (authorizationHeader != null)
            {
                Authenticate(app, authorizationHeader);
            }
            else
            {
                app.Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                app.Context.Response.Flush();
            }
        }

        private void Authenticate(HttpApplication app, string authorizationHeader)
        {
            try
            {
                var authorizationType = authorizationHeader.Split(' ')[0];
                if (authorizationType.Equals(AUTHORIZATION_TYPE))
                {
                    var authenticationData = new AuthenticationData(app.Context);
                    var authenticator = GetAuthenticator(authenticationData);
                    var responseToCache = authenticator.AuthenticateMessage(authenticationData);
                    _cache.Set(authenticationData.SharedKey, responseToCache, null);
                    app.Context.User = new GenericPrincipal(new GenericIdentity(authenticationData.SharedKey, "API"), null);
                }
            }
            catch (SecurityException securityEx)
            {
                app.Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                app.Context.Response.StatusDescription = securityEx.Message;
                app.Context.Response.Flush();
            }
            catch (TimeoutException timeOutEx)
            {
                app.Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                app.Context.Response.SubStatusCode = (int)HttpStatusCode.RequestTimeout;
                app.Context.Response.StatusDescription = timeOutEx.Message;
                app.Context.Response.Flush();
            }
            catch (Exception ex)
            {
                app.Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                app.Context.Response.SubStatusCode = (int)HttpStatusCode.InternalServerError;
                app.Context.Response.Flush();
            }
        }

        private IMessageAuthenticationCodeVerifier GetAuthenticator(AuthenticationData authenticationData)
        {
            IMessageAuthenticationCodeVerifier authenticator;
            SuccessfulResponse cashedResponseData;
            if (_cache.TryGet(authenticationData.SharedKey, out cashedResponseData))
                authenticator = new HMACAuthenticator(cashedResponseData.SecretKey);
            else
                authenticator = new HMACAuthenticator(authenticationData);
            return authenticator;
        }
    }
}
