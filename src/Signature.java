import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.shiro.crypto.hash.Sha256Hash;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.webpki.jcs.JsonCanonicalizer;

public class Signature{
	String endpoint;
	String requestMethod;
	String Key;
	String serviceName;
	String region;
	String algorithm;
	JSONObject headers;
	JSONObject body;
	String httpDoc;
	public Signature(String httpDoc) 
	{
		try {
			this.httpDoc=httpDoc;
			JSONObject json = new JSONObject(httpDoc);
			this.endpoint = json.getString("endpoint");
			this.Key = json.getString("key");
			this.requestMethod = json.getString("requestMethod");
			this.serviceName = json.getString("service");
			this.region = json.getString("region");
			this.headers = json.getJSONObject("headers");
			this.algorithm = json.getString("algorithm");
			if(json.isNull("body"))
				this.body=null;
			else
				this.body = json.getJSONObject("body");

		//	generateCanonicalRequest();
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void print()
	{
		System.out.println(this.endpoint+" "+" "+this.Key+" "+this.headers.toString());
	}

	public String generateCanonicalRequest() throws IOException 
	{
		String canonicalRequest ="";

		// 1.1 : HTTP Method
		canonicalRequest += this.requestMethod.toUpperCase()+"\n";

		// 1.2 : canonical URI with encoding
		URL url;
		try {
			url = new URL(this.endpoint);	
			URI uri = new URI(url.getProtocol(), url.getUserInfo(), url.getHost(), url.getPort(), url.getPath(), url.getQuery(), url.getRef());
			URI normalizeURI = uri.normalize();
			String canonicalURL = normalizeURI.toString();	
			String pattern="com(.*)?[\\?]|com(.*)";
			Pattern r = Pattern.compile(pattern);
			Matcher m = r.matcher(canonicalURL);
			String path="";
			if(m.find())	
				path = m.group(1) == null ? m.group(2) : m.group(1);
			canonicalRequest += path+"\n";
	

			// 1.3 : get encoded canonical query string
			String canonicalQueryString ="";
			String queryString="";
			String newPattern="[\\?](.*)";
			r = Pattern.compile(newPattern);
			m = r.matcher(canonicalURL);
			StringBuilder tempResult = new StringBuilder("");
			if(m.find())
			{
				queryString = m.group(1);				
				String queryParam[] = queryString.split("&");
				Arrays.sort(queryParam);
				for(int i = 0 ; i < queryParam.length; i++)
				{
					if(i == queryParam.length-1)
						tempResult.append(queryParam[i]);
					else
						tempResult.append(queryParam[i] + "&");

				}
			}
			canonicalQueryString =tempResult.toString();
			canonicalRequest += canonicalQueryString+"\n";
	

			//1.4 & 1.5 :	Create canonical headers And Signed Headers
			String tmpResult="";
			StringBuilder signedHeaders=new StringBuilder("");
			Iterator it =this.headers.sortedKeys();
			while(it.hasNext())
			{
				String key=(String)it.next();
				String value =this.headers.getString(key);
				String k = key.trim().toLowerCase();
				signedHeaders.append(k);
				signedHeaders.append(";");
				String v = value.trim().replaceAll(" +", " ");
				tmpResult +=k+":"+v+"\n";
			}
			signedHeaders.deleteCharAt(signedHeaders.length()-1);
			canonicalRequest += tmpResult+"\n";
			canonicalRequest += signedHeaders+"\n";

			//1.6 : SHA256 on body
			if(this.body != null)
			{
				String boody = this.body.toString();
			
				System.out.println("###################################################");
				JsonCanonicalizer jsonCanonicalizer = new JsonCanonicalizer(boody);
			    String result = jsonCanonicalizer.getEncodedString();
				System.out.println(result);
				Sha256Hash sha=new Sha256Hash(result);
				System.out.println(sha.toHex());
				canonicalRequest += sha.toHex();
			}
			else
			{
				Sha256Hash sha=new Sha256Hash("");
				System.out.println(sha.toHex());
				canonicalRequest += sha.toHex().toString();
			}
			return canonicalRequest;



		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";

	}

	public String prepareStringToSign(String canonicalURL) throws JSONException {
		String stringToSign = "";
		stringToSign = this.algorithm + "\n";
		String xDate = this.headers.getString("x-amz-date");
		stringToSign += xDate+"\n";

		int pos = xDate.indexOf("T");
		String date = xDate.substring(0, pos);

		String scope=date+"/"+this.region+"/"+this.serviceName+"/"+"aws4_request";
		stringToSign += scope+"\n";

		Sha256Hash sha = new Sha256Hash(canonicalURL);
		stringToSign += sha.toString();
//		System.out.println("-------------------Prepare String To Sign----------------------");
//		System.out.println(stringToSign);


		return stringToSign;


	}
	
	
	public static byte[] computePayloadSHA256Hash2(byte[] payload) throws NoSuchAlgorithmException, IOException {
	    BufferedInputStream bis = 
	       new BufferedInputStream(new ByteArrayInputStream(payload));
	    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
	    byte[] buffer = new byte[4096];
	    int bytesRead = -1;
	    while ( (bytesRead = bis.read(buffer, 0, buffer.length)) != -1 ) {
	        messageDigest.update(buffer, 0, bytesRead);
	    }
	    return messageDigest.digest();
	}
	
	

	public String getSignature() throws IOException 
	{

		String canonicalRequest = generateCanonicalRequest();
		System.out.println("**************canonicalRequest***********************");
		System.out.println(canonicalRequest);
		String stringToSign;
		String signature="";
				try {
					stringToSign = prepareStringToSign(canonicalRequest);
					System.out.println("*********************stringToSign*************************");
					System.out.println(stringToSign);
					SignatureGeneration sg = new SignatureGeneration();
					String xDate = this.headers.getString("x-amz-date");
					int pos = xDate.indexOf("T");
					String date=xDate.substring(0, pos);

					signature = sg.calculateSignature(this.Key, date, this.region, this.serviceName, "aws4_request", stringToSign);
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalStateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (UnsupportedEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}






		return signature;

	}


}
