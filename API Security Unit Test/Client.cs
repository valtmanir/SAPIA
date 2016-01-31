using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Web;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Globalization;
using System.Configuration;
using System.Xml.Linq;
using System.Threading;
using SAPIA_NET_Client_SDK;


namespace SAPIA_NET_Client_SDK_Unit_Test
{
    [TestClass]
    public class SDKClientShould
    {
        private Uri BASE_ADDRESS = new Uri(@"http://127.0.0.1/SAPIA/");
        private const string SECRET_KEY = "MyDemoSecretKey123";
        private const string SHARED_KEY = "MyDemoSharedKeyABC";

        [TestMethod]
        public void PerformASuccessfulGetRequest()
        {
            var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS);
            var dataStream = webClient.OpenRead(BASE_ADDRESS.AbsoluteUri);          
        }

        [TestMethod]
        public void PerformSuccessfulPostRequestWithShortPayload()
        {
            var data = "AnyData";
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
            var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, data);
        }

        [TestMethod]
        public void PerformSuccessfulPostRequestWithLongPayload()
        {
            var data = "AnyData";
            while (data.Length <= SecureWebClient.MaxPayloadBytes)
                data += data;
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
            var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, data);
        }

        [TestMethod]
        public void TamperPayloadAndRecieveUnauthorizedResponse()
        {
            var data = "AnyData";
            var tamperedData = String.Format("{0}{1}", data, data);
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, tamperedData);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        [TestMethod]
        public void SendTimedOutRequestAndRecieveUnauthorizedResponse()
        {
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS);
                var timeToSleep = GetRequestTimeOut();
                Thread.Sleep(timeToSleep);
                var dataStream = webClient.OpenRead(BASE_ADDRESS.AbsoluteUri);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        [TestMethod]
        public void SendTamperedTimeStampAndRecieveUnauthorizedResponse()
        {
            var data = "AnyData";
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                var headerValue = webClient.Headers.Get(HttpRequestHeader.Authorization.ToString()).Replace("API ", "");
                var decodedHeaderValue = Base64Decode(headerValue);
                var decodedHeaderSplitValues = decodedHeaderValue.Split(':');
                
                var tamperedTimeStamp = DateTime.Now.AddHours(1).ToString("MM/dd/yyyy hh:mm:ss tt");
                var tamperedTimeStampBytes = System.Text.Encoding.UTF8.GetBytes(tamperedTimeStamp);
                var encodedTimeStamp = Convert.ToBase64String(tamperedTimeStampBytes);

                var tamperedHeaderValue = String.Format("{0}:{1}:{2}", decodedHeaderSplitValues[0], encodedTimeStamp, decodedHeaderSplitValues[2]);
                var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(headerValue);
                
                webClient.Headers.Clear();
                webClient.Headers.Add(HttpRequestHeader.Authorization.ToString(), String.Format("{0} {1}", "API ", Convert.ToBase64String(plainTextBytes)));

                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, data);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        [TestMethod]
        public void SendTamperedTimeStampFormatAndRecieveUnauthorizedResponse()
        {
            var data = "AnyData";
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                var headerValue = webClient.Headers.Get(HttpRequestHeader.Authorization.ToString()).Replace("API ", "");
                var decodedHeaderValue = Base64Decode(headerValue);
                var decodedHeaderSplitValues = decodedHeaderValue.Split(':');

                var tamperedTimeStamp = "Any non-parsed DateTime value";
                var tamperedTimeStampBytes = System.Text.Encoding.UTF8.GetBytes(tamperedTimeStamp);
                var encodedTimeStamp = Convert.ToBase64String(tamperedTimeStampBytes);

                var tamperedHeaderValue = String.Format("{0}:{1}:{2}", decodedHeaderSplitValues[0], encodedTimeStamp, decodedHeaderSplitValues[2]);
                var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(headerValue);

                webClient.Headers.Clear();
                webClient.Headers.Add(HttpRequestHeader.Authorization.ToString(), String.Format("{0} {1}", "API ", Convert.ToBase64String(plainTextBytes)));

                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, data);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        [TestMethod]
        public void SendTamperedURIAndRecieveUnauthorizedResponse()
        {
            var data = "AnyData";
            var tamperedData = String.Format("{0}{1}", data, data);
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                var tamperedURI = new Uri(String.Format("{0}{1}", BASE_ADDRESS.AbsoluteUri, "CrawledURI"));
                webClient.BaseAddress = tamperedURI.AbsoluteUri;
                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, tamperedData);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }    
        }

        [TestMethod]
        public void RemoveAuthorizationHeaderAndRecieveUnauthorizedResponse()
        {
            var data = "AnyData";
            var tamperedData = String.Format("{0}{1}", data, data);
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                webClient.Headers.Clear();
                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, tamperedData);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        [TestMethod]
        public void SendEmptyAuthorizationValueAndRecieveUnauthorizedResponse()
        {
            var data = "AnyData";
            var tamperedData = String.Format("{0}{1}", data, data);
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                webClient.Headers.Clear();
                webClient.Headers.Add(HttpRequestHeader.Authorization.ToString(), "API ");
                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, tamperedData);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        [TestMethod]
        public void SendEmptyAuthorizationHeadeAndRecieveUnauthorizedResponser()
        {
            var data = "AnyData";
            var tamperedData = String.Format("{0}{1}", data, data);
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                webClient.Headers.Clear();
                webClient.Headers.Add(HttpRequestHeader.Authorization.ToString(), "");
                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, tamperedData);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        [TestMethod]
        public void SendTamperedSharedKeyAndRecieveUnauthorizedResponse()
        {
            var data = "AnyData";
            var payload = new MemoryStream(Encoding.UTF8.GetBytes(data));
            try
            {
                var webClient = new SecureWebClient(SECRET_KEY, SHARED_KEY, BASE_ADDRESS, payload);
                var headerValue = webClient.Headers.Get(HttpRequestHeader.Authorization.ToString()).Replace("API ", "");
                var decodedHeaderValue = Base64Decode(headerValue);
                var decodedHeaderSplitValues = decodedHeaderValue.Split(':');

                var tamperedSharedKey = String.Format("{0}{1}", decodedHeaderSplitValues[0], "1");
                var tamperedHeaderValue = String.Format("{0}:{1}:{2}", tamperedSharedKey, decodedHeaderSplitValues[1], decodedHeaderSplitValues[2]);
                var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(headerValue);

                webClient.Headers.Clear();
                webClient.Headers.Add(HttpRequestHeader.Authorization.ToString(), String.Format("{0} {1}", "API ", Convert.ToBase64String(plainTextBytes)));

                var dataStream = webClient.UploadString(BASE_ADDRESS.AbsoluteUri, data);
            }
            catch (WebException ex)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                Assert.IsTrue(HttpStatusCode.Unauthorized.Equals(statusCode));
            }
        }

        private string Base64Decode(string encodedString)
        {
            var byteArrayToDecode = System.Convert.FromBase64String(encodedString);
            return Encoding.UTF8.GetString(byteArrayToDecode);
        }

        private int GetRequestTimeOut()
        {
            var filePath = String.Format("{0}{1}", Directory.GetCurrentDirectory(), @"\..\..\..\DemoWebApp\bin\app.config");
            var xdoc = XDocument.Load(filePath);
            var strSettingElement = xdoc.Element("configuration").Element("applicationSettings").Element("SAPIA_Server_SDK.Properties.Settings").FirstNode.NextNode.ToString();
            var settingElement = XDocument.Load(new MemoryStream(Encoding.UTF8.GetBytes(strSettingElement)));
            return int.Parse(settingElement.Element("setting").Element("value").Value);
        }
    }
}
