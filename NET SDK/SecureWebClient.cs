using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SAPIA_NET_Client_SDK
{
    public class SecureWebClient : WebClient
    {
        private static string _secretKey, _sharedKey;
        private const string AUTHORIZATION_TYPE = "API";


        public SecureWebClient(string SecretKey, string SharedKey, Uri URI) : base() 
        {
            _secretKey = SecretKey;
            _sharedKey = SharedKey;
            MaxPayloadBytes = 1024;
            var header = GetHeader(URI, new MemoryStream());
            base.Headers.Add(header.Key, header.Value);
        }

        public SecureWebClient(string SecretKey, string SharedKey, Uri URI, Stream payload) : base()
        {
            _secretKey = SecretKey;
            _sharedKey = SharedKey;
            MaxPayloadBytes = 1024;
            var header = GetHeader(URI, payload);
            base.Headers.Add(header.Key, header.Value);
        }

        public static int MaxPayloadBytes { get; set; }

        private KeyValuePair<HttpRequestHeader, string> GetHeader(Uri uri, Stream payload)
        {
            var now = DateTime.Now;
            var currentTimeStamp = now.ToString("MM/dd/yyyy hh:mm:ss tt");
            var payloadToHash = GetStreamToHash(payload);
            var calculatedHMACString = GetHMAC(uri, payloadToHash, currentTimeStamp);
            var currentTimeStampBytes = System.Text.Encoding.UTF8.GetBytes(currentTimeStamp);
            var encodedTimeStamp = Convert.ToBase64String(currentTimeStampBytes);
            var headerValue = String.Format("{0}:{1}:{2}", _sharedKey, encodedTimeStamp, calculatedHMACString);
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(headerValue);
            var headerBase64Value = String.Format("{0} {1}", AUTHORIZATION_TYPE, Convert.ToBase64String(plainTextBytes));
            return new KeyValuePair<HttpRequestHeader, string>(HttpRequestHeader.Authorization, headerBase64Value);
        }

        private static string GetHMAC(Uri uri, string payload, string currentTimeStamp)
        {
            var hmac = InitHMAC();
            var concatenatedAuthenticationData = String.Format("{0}:{1}:{2}", currentTimeStamp, uri.AbsolutePath, payload);
            var calculatedHMACBytes = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(concatenatedAuthenticationData));
            var calculatedHMACString = ByteArrayToString(calculatedHMACBytes);
            return calculatedHMACString;
        }

        private static HMACSHA256 InitHMAC()
        {
            var hmac = new HMACSHA256();
            hmac.Key = Encoding.UTF8.GetBytes(_secretKey);
            return hmac;
        }

        private static string ByteArrayToString(byte[] byteArray)
        {
            string hex = BitConverter.ToString(byteArray);
            return hex.Replace("-", "");
        }

        private string GetStreamToHash(Stream stream)
        {
            var payload = "";
            if (stream.Length > 0)
            {
                using (var bufferedStream = new BufferedStream(stream, MaxPayloadBytes))
                    using (var streamReader = new StreamReader(bufferedStream))
                    {
                        if (stream.Length <= MaxPayloadBytes)
                            payload = streamReader.ReadToEnd();
                        else
                        {
                            var payloadBuffer = new char[MaxPayloadBytes];
                            streamReader.Read(payloadBuffer, 0, MaxPayloadBytes);
                            payload = new string(payloadBuffer);
                        }
                        if (stream.CanSeek)
                            stream.Position = 0;
                    }
            }
            return payload;
        }
    }
}
