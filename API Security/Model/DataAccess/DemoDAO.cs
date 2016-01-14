using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SAPIA.Model.DataAccess
{
    public class DemoDAO : IDataAccessObject
    {

        public string GetSecretKey(string sharedKey)
        {
            if (sharedKey.Equals("MyDemoSharedKeyABC"))
                return "MyDemoSecretKey123";
            return null;
        }

        public bool StoreKeyPair(string secretKey, string sharedKey, object additionalIdentityData)
        {
            return true;
        }
    }
}