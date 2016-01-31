using SAPIA_NET_Server_IDataAccessObject;
using SAPIA_NET_Server_DataAccessObject;
using SAPIA_NET_Server_SDK.Model.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace SAPIA_NET_Server_SDK.Model.Cryptography
{
    internal class HMACAuthenticator : IMessageAuthenticationCodeVerifier, IDisposable
    {
        private HMACSHA256 _hmac = new HMACSHA256();
        private static IDataAccessObject _dao = new DAO();
        private static readonly int maxPayloadBytes = Properties.Settings.Default.PayloadBytesToAuthenticate;
        private static readonly int maxtTimeout = Properties.Settings.Default.MaxTimeout;
        private static readonly bool isTimeoutVerificationEnabled = Properties.Settings.Default.IsTimeoutVerificationEnabled;

        public HMACAuthenticator(string secretKey)
        {
            _hmac.Key = Encoding.UTF8.GetBytes(secretKey);
        }

        public HMACAuthenticator(AuthenticationData authenticationData)
        {
            string secretKey = _dao.GetSecretKey(authenticationData.SharedKey);
            if (secretKey == null)
                throw new SecurityException("Invalid shared key");
            _hmac.Key = Encoding.UTF8.GetBytes(secretKey);
        }

        public SuccessfulResponse AuthenticateMessage(AuthenticationData authenticationData)
        {
            if (isTimeoutVerificationEnabled)
            {
                var authenticationDataUtcTimeStamp = TimeZoneInfo.ConvertTimeToUtc(authenticationData.TimeStamp);
                if (authenticationDataUtcTimeStamp.CompareTo(DateTime.UtcNow.AddMilliseconds(-1 * maxtTimeout)) < 0)
                    throw new TimeoutException("The message timed out.");
            }
            var timeStamp = authenticationData.TimeStamp.ToString("MM/dd/yyyy hh:mm:ss tt");
            var concatenatedAuthenticationData = String.Format("{0}:{1}:{2}", timeStamp, authenticationData.URI.AbsolutePath, authenticationData.Payload);
            var calculatedHMACBytes = _hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(concatenatedAuthenticationData));
            var calculatedHMACString = ByteArrayToString(calculatedHMACBytes);
            if (!calculatedHMACString.Equals(authenticationData.MessageAuthenticationCode))
                throw new SecurityException("Could not verify the integrity of the message");
            return new SuccessfulResponse(Encoding.UTF8.GetString(_hmac.Key), new object());
        }

        private static string ByteArrayToString(byte[] byteArray)
        {
            string hex = BitConverter.ToString(byteArray);
            return hex.Replace("-", "");
        }


        public void Dispose()
        {
            _hmac.Dispose();
            GC.SuppressFinalize(this);
        }

    }
}