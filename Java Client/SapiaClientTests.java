import org.eclipse.jetty.util.StringUtil;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

/**
 * Created by Pavel Yankelevich on 4/11/2016.
 */
public class SapiaClientTests {

    @Test
    public void checkHeaderSet(){
        String https_url = "http://localhost/SAPIA/Hello.asmx";
        URL url;
        try {
            url = new URL(https_url);
            //Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 9090));
            //HttpURLConnection urlConnection = (HttpURLConnection)url.openConnection(proxy);

            HttpURLConnection urlConnection = (HttpURLConnection)url.openConnection();
            //HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();

            SapiaClient.MaxPayloadBytes =  0;
            SapiaClient.AddSapiaAuthentication(urlConnection, "MyDemoSecretKey123", "MyDemoSharedKeyABC");

            int responseCode = urlConnection.getResponseCode();
            assertEquals(200, responseCode);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void checkHeaderSetWithPayload() throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        String https_url = "http://localhost/SAPIA/Hello.asmx/HelloWorldPost";
        URL url;
        try {
            url = new URL(https_url);
            HttpURLConnection urlConnection = (HttpURLConnection)url.openConnection();
            int responseCode;

            String payloadString = "postData=1234567890-1234567890-1234567890-1234567890";
            byte[] postData = payloadString.getBytes("UTF8");
            InputStream payload = new ByteArrayInputStream(postData);
            int    postDataLength = postData.length;

            SapiaClient.MaxPayloadBytes =  1024;
            SapiaClient.AddSapiaAuthentication(urlConnection, "MyDemoSecretKey123", "MyDemoSharedKeyABC", payload);

            urlConnection.setDoOutput( true );
            urlConnection.setInstanceFollowRedirects( false );
            urlConnection.setRequestMethod( "POST" );
            urlConnection.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded");
            urlConnection.setRequestProperty( "charset", "utf-8");
            urlConnection.setRequestProperty( "Content-Length", Integer.toString( postDataLength ));
            urlConnection.setUseCaches( false );
            try( DataOutputStream wr = new DataOutputStream( urlConnection.getOutputStream())) {
                wr.write( postData );
            }

            responseCode = urlConnection.getResponseCode();
            assertEquals(200, responseCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
