///keytool -genkey -alias wso2carbon -keyalg RSA -keysize 2048 -keystore teststore.jks -dname "CN=test.com, OU=Home,O=Home,L=SL,S=WS,C=LK" -storepass wso2carbon -keypass wso2carbon
///
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System;
using Microsoft.IdentityModel.Tokens;

Console.WriteLine("JWT Signature Validator");
Console.WriteLine("Type 1 >> To Validate \nType 2 >> To Sign");
int mode = 0;
int.TryParse(Console.ReadLine(), out mode);
if (mode == 1)//validate
{
    Console.WriteLine("Insert JWT");
    var jwt = Console.ReadLine();
    var jwtParts = jwt.Split('.');
    if (jwtParts.Length != 3)
    {
        Console.WriteLine("Invalid Token");
        return;
    }
    var header = jwtParts[0];
    var payload = jwtParts[1];
    var signature = jwtParts[2];

    Console.WriteLine("Public Key Certificate File");
    var publicKey = Console.ReadLine();
    var isvalid = VerifySignature(Encoding.UTF8.GetBytes($"{header}.{payload}"), Base64UrlEncoder.DecodeBytes(signature), publicKey);

    Console.WriteLine("Is JWT Token Is Valid ? " + (isvalid ? "Yes" : "NO"));
}
else if (mode == 2) //sign
{
    Console.WriteLine("pkcs12 File");
    var pkcs12File = Console.ReadLine();
    Console.WriteLine("pkcs12 File Password");
    var pkcs12Password = Console.ReadLine();
    Console.WriteLine("Insert Header");
    var header = Base64UrlEncoder.Encode(Console.ReadLine());
    Console.WriteLine("Insert Payload");
    var payload = Base64UrlEncoder.Encode(Console.ReadLine());
    var signature = SignData(Encoding.UTF8.GetBytes($"{header}.{payload}"), pkcs12File, pkcs12Password);
    Console.WriteLine("Signed JWT");
    Console.WriteLine($"{header}.{payload}.{Base64UrlEncoder.Encode(signature)}");

}
else
{
    Console.WriteLine("Invalid Input");
}
static byte[] SignData(byte[] data, string pkcs12File, string pkcs12Password)
{
    X509Certificate2 signerCert = new X509Certificate2(pkcs12File, pkcs12Password, X509KeyStorageFlags.Exportable);
    var rsaCSP = signerCert.GetRSAPrivateKey();
    if (rsaCSP == null)
        return null;
    return rsaCSP.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

}
static bool VerifySignature(byte[] data, byte[] signature, string publicCert)
{
    X509Certificate2 partnerCert = new X509Certificate2(publicCert);
    var rsaCSP = partnerCert.GetRSAPublicKey();
    if (rsaCSP == null)
        return false;
    return rsaCSP.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
}
