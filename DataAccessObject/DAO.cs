using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SAPIA_NET_Server_IDataAccessObject;

namespace SAPIA_NET_Server_DataAccessObject

{
    public class DAO : IDataAccessObject
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
