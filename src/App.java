public class App {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello, World!");
        String hd = "{\n  \"service\": \"ec2\",\n  \"region\": \"us-east-1\",\n  \"key\": \"23478207027842073230762374023\",\n  \"endpoint\": \"https://ec2.amazonaws.com\",\n  \"requestMethod\": \"GET\",\n  \"algorithm\": \"AWS4-HMAC-SHA256\",\n  \"headers\": {\n    \"Content-Type\": \"application/json\",\n    \"x-amz-Date\": \"Mon, 12 Nov 2007 10:49:58 GMT\"\n  },\n  \"body\": null\n}";
        Signature sn = new Signature(hd);
        sn.getSignature();
    }
}
