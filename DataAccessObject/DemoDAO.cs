using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DataAccessObject
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
