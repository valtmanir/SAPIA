using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Runtime.Caching;
using System.Web;

namespace SAPIA_NET_Server_SDK.Model
{
    internal class SuccessfulResponse
    {

        public SuccessfulResponse(string SecretKey, object Identity)
        {
            this.SecretKey = SecretKey;
            this.Identity = Identity;
        }
        public string SecretKey { get; private set; }

        public object Identity { get; private set; }
    }

    internal class SuccesfulResponseCache : MemoryCache
    {
        private CacheItemPolicy HardDefaultCacheItemPolicy = new CacheItemPolicy()
        {
            
            SlidingExpiration = new TimeSpan(0,Properties.Settings.Default.ResponseDataExpirationTimeInMinutes,0)
        };

        private CacheItemPolicy defaultCacheItemPolicy;

        public SuccesfulResponseCache(string name, NameValueCollection nvc = null, CacheItemPolicy policy = null)
            : base(name, nvc)
        {
            defaultCacheItemPolicy = policy ?? HardDefaultCacheItemPolicy;
        }

        public void Set(string cacheKey, SuccessfulResponse cacheItem, CacheItemPolicy policy = null)
        {
            policy = policy ?? defaultCacheItemPolicy;
            base.Set(cacheKey, cacheItem, policy);
        }

        public bool TryGet(string cacheKey, out SuccessfulResponse returnItem)
        {
            returnItem = (SuccessfulResponse)this[cacheKey];
            return returnItem != null;
        }

    }
}