# Secure API Authentication (SAPIA)

The SAPIA project has been established in order to enable a secure and highly performing ***non-interatvie user authentication to APIs***. Although the approach can be leveraged by interactive users as well, there are other various supported authentication protocols in the field that can be examined. 

## Introduction
The SAPIA project provides a standard .NET based HTTP handler for web and application servers, which provide the first protection gate for all the application endpoints that protected by it. 
This project consist of both server-side and client-side functionality. The server side performs the authentication and integirty validations, while the client side is provided in a form of SDK for generating the requests to the server.

## Common Lacking API Authentication Methods
There are many authentication protocols allowing users to ineract with software, however, software components are also requesred to authenticate to APIs securely. The software components are propriatary clients, e.g. platform, batch, kiosk applications, reverse-proxy based gateways etc.

The common ***API*** authentication methods are based on the following three types:

1. Credentials - mostly a username and password combination. 
2. Client certificate authentication.
3. Access token from a trusted centralized authentication system.

These authentication mechanisms are lacking as described below:

| Authentication Method  | Disadvantage  |
|:---------------------- |:--------------|
| Credentials            | A non-interactive user is being authenticated once and then the software needs to manage the session.|
| Client Certificate     | Client certificate authentication requires costly cryptography operations for every request.|
| Access Token           | Although Access Tokens are widely spread, these protocols are chatty, i.e. they are required to generate requests to a centralized authentication server every time the access token expires or the user needs to authentication. In this approach, it is also required to manage the timeout of the Access Token on the client side (even if it is only related to handling the timeout and reauthentication requests from the server).|

## SAPIA's Features

### Integrity Validation
All requests are validated against tampering attacks by performing validation of the message authentication code, which consist of the URI, the payload data and the timestamp it was generated. 

### Anti-Replay Attack Protection
As described above, all requests are generated with a timestamp and its message authentication code. The request timeout is defined on the server side (by default 5 seconds), which prevents from any validated request to be processed in case the timestamp is not in the configured timeframe. 

### Denial of Service / Resource Exhaustion
Malicious users may try to execute a denial of service (DOS) attack, which enforces the server to generate a message authentication code on a big amount of data for every request. Thus, SAPIA allows to configure a parameter of the maximum payload to calculate, i.e. the payload remains the same, but the amount of bytes that calculated in the message authentication code function is limited.
Obviously, such functionality may expose a vulnerability in the application, but this is where the risk management process takes place.

### Performance
The SAPIA project uses the HMAC-256 algorithm out of the box in order to generate the message authentication code. This algorithm is not considered as heavy cryptographic consumer, however, the message authentication interface can be implented using different hashing or symmetric encryption mechanisms.

The additional factor that improves the performance is the memory cache of the authentication response, which allows to cache the identity information and the secret key. As result, in case of hitting the cache, the HMAC will be performed immediately without generating a request to the database for every API call.

### Loosely Coupled Persistance Layer
SAPIA does not handle any persistance of the data but only provides an interface for implementing the required requests for data. It is the developer's responsability to implement the data access objects, and therefore, SAPIA remains loosely coupled. 

### Developers Developers Developers!
The client side is transparent to any server-side configurations. Include the DLL and simply use the SDK, which extends the common WebClient class.

## Pre-requisites
* IIS Server with anonymous authentication enabled.
* .NET framework 4 and above.

## License
This open source project is published under [MIT license](https://github.com/valtmanir/SAPIA/blob/master/LICENSE).
