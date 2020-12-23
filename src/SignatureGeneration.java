
//<script src="https://gist.github.com/phstudy/3523576726d74a0410f8.js"></script>

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.shiro.codec.Hex;

public class SignatureGeneration {

	
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

  public static byte[] computeHmacSHA256(byte[] key, String data) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
          UnsupportedEncodingException {
      String algorithm = "HmacSHA256";
      String charsetName = "UTF-8";

      Mac sha256_HMAC = Mac.getInstance(algorithm);
      SecretKeySpec secret_key = new SecretKeySpec(key, algorithm);
      sha256_HMAC.init(secret_key);

      return sha256_HMAC.doFinal(data.getBytes(charsetName));
  }

  public static byte[] computeHmacSHA256(String key, String data) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
          UnsupportedEncodingException {
      return computeHmacSHA256(key.getBytes(), data);
  }

  public static String getSignatureV4(String accessSecretKey, String date, String region, String regionService, String signing, String stringToSign)
          throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException {

      byte[] dateKey = computeHmacSHA256(accessSecretKey, date);
 

      byte[] dateRegionKey = computeHmacSHA256(dateKey, region);
  

      byte[] dateRegionServiceKey = computeHmacSHA256(dateRegionKey, regionService);


      byte[] signingKey = computeHmacSHA256(dateRegionServiceKey, signing);
      
      
      System.out.println(SignatureGeneration.bytesToHex(signingKey));

      byte[] signature = computeHmacSHA256(signingKey, stringToSign);
 

      return Hex.encodeToString(signature);
  }

  public  String calculateSignature(String accessSecretKey,String date,String region,String regionService,String signing,String stringToSign) throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException {

 /*     String accessSecretKey = "AWS4" + "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
      String date = "20150830";
      String region = "us-east-1";
      String regionService = "iam";
      String signing = "aws4_request";
      String stringToSign = "AWS4-HMAC-SHA256\n" + 
      		"20150830T123600Z\n" + 
      		"20150830/us-east-1/iam/aws4_request\n" + 
      		"f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";*/

  
      String result = getSignatureV4("AWS4"+accessSecretKey, date, region, regionService, signing, stringToSign);
      System.out.println(result);
     return result;
     
  }

}
