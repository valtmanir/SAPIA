using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.IO;
using System.Security;
using System.Text;
using System.Globalization;

namespace SAPIA_NET_Server_SDK.Model
{
    internal class AuthenticationData
    {
        private static readonly int maxPayloadBytes = Properties.Settings.Default.PayloadBytesToAuthenticate;
        private const string AUTHORIZATION_TYPE = "API";

        public AuthenticationData(HttpContext context)
        {
            SetURI(context);
            ExtractHeaderInformation(context);
            SetMaximumPayload(context);
        }

        public string SharedKey { get; private set; }

        public Uri URI { get; private set; }

        public string Payload { get; private set; }

        public DateTime TimeStamp { get; private set; }

        public string MessageAuthenticationCode { get; private set; }

        private void SetURI(HttpContext context)
        {
            URI = context.Request.Url;
        }

        private void ExtractHeaderInformation(HttpContext context)
        {
            var authorizationHeaderValue = GetDecodedAuthorizationHeaderValue(context);
            var authorizationHeaderValueStrings = authorizationHeaderValue.Split(':');
            if (authorizationHeaderValueStrings.Length != 3)
                throw new SecurityException("Could not verify the Authorization header");
            SharedKey = authorizationHeaderValueStrings[0];
            TimeStamp = GetParsedTimeStamp(authorizationHeaderValueStrings[1]);
            MessageAuthenticationCode = authorizationHeaderValueStrings[2];
        }

        private DateTime GetParsedTimeStamp(string base64EncodedTimeStamp)
        {
            var decodedTimeStampString = Base64Decode(base64EncodedTimeStamp);
            DateTime timeStamp;
            if (DateTime.TryParseExact(decodedTimeStampString, "MM/dd/yyyy hh:mm:ss tt", CultureInfo.InvariantCulture, DateTimeStyles.None, out timeStamp))
                return timeStamp;
            throw new SecurityException("Invalid authorization data");
        }

        private void SetMaximumPayload(HttpContext context) {
            Payload = "";
            var inputStream = context.Request.InputStream;
            if (inputStream.Length > 0)
            {
                var bytesToRead = (int) (inputStream.Length <= maxPayloadBytes ? inputStream.Length : maxPayloadBytes); 
                var payloadBuffer = new byte[bytesToRead];
                inputStream.Read(payloadBuffer, 0, bytesToRead);
                Payload = Encoding.ASCII.GetString(payloadBuffer);
            }
        }

        private string GetDecodedAuthorizationHeaderValue(HttpContext context)
        {
            var headerValue = context.Request.Headers["Authorization"];
            var headerValueStrings = headerValue.Split(' ');
            if (headerValueStrings.Length < 2)
                throw new SecurityException("Incorrect Authorization Header");
            var authorizationData = headerValueStrings[1];
            return Base64Decode(authorizationData);
        }

        private string Base64Decode(string encodedString)
        {
            var byteArrayToDecode = System.Convert.FromBase64String(encodedString);
            return Encoding.UTF8.GetString(byteArrayToDecode);
        }

    }
}