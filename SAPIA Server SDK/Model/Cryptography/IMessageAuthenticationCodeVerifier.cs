﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SAPIA_NET_Server_SDK.Model;

namespace SAPIA_NET_Server_SDK.Model.Cryptography
{
    internal interface IMessageAuthenticationCodeVerifier
    {
        // This method authenticates the message and returns any relevant data according to the business logic
        // of the application, e.g. full identity, roles, claims etc. 
        // Tweak the SuccessfulResponse class as you need.
        SuccessfulResponse AuthenticateMessage(AuthenticationData authenticationData);


    }
}
