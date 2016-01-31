using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DataAccessObject
{
    public interface IDataAccessObject
    {
        // This methods retrieved the secret key of the identity based on the shared key.
        string GetSecretKey(string sharedKey);

        // The method persists the key pair (secret and shared keys) for a given identity.
        // If the key pair succesfully persisted, themethod returns true.
        bool StoreKeyPair(string secretKey, string sharedKey, object additionalIdentityData);
    }
}
