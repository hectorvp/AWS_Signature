## Folder Structure

The workspace contains two folders by default, where:

- `src`: the folder to maintain sources
- `lib`: the folder to maintain dependencies

## Input

HTTP message in taken as input in JSON format, JSON structure is


{  
  "service": "ec2",  
  "region": "us-east-1",  
  "key": "23478207027842073230762374023",  
  "endpoint": "https://ec2.amazonaws.com",  
  "requestMethod": "GET",  
  "algorithm": "AWS4-HMAC-SHA256",  
  "headers": {  
    "Content-Type": "application/json",  
    "x-amz-Date": "Mon, 12 Nov 2007 10:49:58 GMT"  
  },  
  "body": null  
}  

## Driver Code
Signature sn = new Signature(<Input JSON in String format>);  
sn.getSignature();  


This driver code is written in APP.java, one can check it as a reference


## Output

Output is the signature as shown below:  
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

## Dependencies
- shiro-core.jar
- org.json.jar
- json-canonicalizer.jar


    