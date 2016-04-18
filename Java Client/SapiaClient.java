import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

public class SapiaClient {
    private static final String AUTHORIZATION_TYPE = "API";

    public static int MaxPayloadBytes;

    public static void AddSapiaAuthentication(URLConnection connection, String SecretKey, String SharedKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        String url = connection.getURL().getPath();

        String headerBase64Value = buildHeader(SecretKey, SharedKey, url, "");

        connection.setRequestProperty("Authorization", headerBase64Value);
    }

    public static void AddSapiaAuthentication(URLConnection connection, String SecretKey, String SharedKey, InputStream payload) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        String url = connection.getURL().getPath();

        String payloadToHash = GetStreamToHash(payload);
        String headerBase64Value = buildHeader(SecretKey, SharedKey, url, payloadToHash);

        connection.setRequestProperty("Authorization", headerBase64Value);
    }

    private static String buildHeader(String SecretKey, String SharedKey, String url, String payloadToHash) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy hh:mm:ss a");
        String currentTimeStamp = dateFormat.format(new Date());
        String calculatedHMACString = GetHMAC(url, payloadToHash, currentTimeStamp, SecretKey);
        byte[] currentTimeStampBytes = currentTimeStamp.getBytes("UTF8");
        String encodedTimeStamp = Base64.encodeBase64String(currentTimeStampBytes);
        String headerValue = String.format("%s:%s:%s", SharedKey, encodedTimeStamp, calculatedHMACString);
        byte[] plainTextBytes = headerValue.getBytes("UTF8");
        return String.format("%s %s", AUTHORIZATION_TYPE, Base64.encodeBase64String(plainTextBytes));
    }

    private static String GetHMAC(String url, String payloadToHash, String currentTimeStamp, String secretKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(secretKey.getBytes("UTF8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);

        String concatenatedAuthenticationData = String.format("%s:%s:%s", currentTimeStamp, url, payloadToHash);

        return bytesToHex(sha256_HMAC.doFinal(concatenatedAuthenticationData.getBytes("UTF8")));
    }

    private static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static String GetStreamToHash(InputStream payloadStream) throws IOException {
        String payload = "";
        if (payloadStream.available()>0 && MaxPayloadBytes > 0){
            byte[] buffer = new byte[MaxPayloadBytes];
            if (payloadStream.markSupported())
                payloadStream.mark(MaxPayloadBytes);
            int read = payloadStream.read(buffer, 0, MaxPayloadBytes);
            if (read > 0){
                byte[] payloadBytes = Arrays.copyOf(buffer, read);
                payload = new String(payloadBytes);

                if (payloadStream.markSupported())
                    payloadStream.reset();
            }
        }
        return payload;
    }
}
