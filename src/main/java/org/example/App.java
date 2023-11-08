package org.example;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class App {
    private static final String privateKeyPath = "F:\\Keys\\PrivateKey";
    private static final String publicKeyPath = "F:\\Keys\\PublicKey";

    private static final RSAKeyGenerator keyGenerator = new RSAKeyGenerator(1024);
    private static final SignService signService = new SignService();

    public static void main( String[] args ) throws Exception {
        keyGenerator.WriteToFile(privateKeyPath, keyGenerator.getPrivateKey().getEncoded());
        keyGenerator.WriteToFile(publicKeyPath, keyGenerator.getPublicKey().getEncoded());

        var msg = "Nguyen Viet Hung";
        var messageDigest = MessageDigest.getInstance("SHA-256");
        var messageHash = messageDigest.digest(msg.getBytes(StandardCharsets.UTF_8));

        var privateKey = (PrivateKey) signService.loadKey(privateKeyPath, SignService.KeyTypes.Private);
        var signature = signService.encryptText(messageHash, privateKey);

        System.out.println("---A send---");
        System.out.println("Message:   " + msg);
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));
        System.out.println();

        var publicKey = (PublicKey) signService.loadKey(publicKeyPath, SignService.KeyTypes.Public);
        var decodeSignature = signService.decryptText(signature, publicKey);

        System.out.println("---B receive---");
        System.out.println("Message:          " + msg);
        System.out.println("A Signature:      " + Base64.getEncoder().encodeToString(signature));
        System.out.println("Hash message:     " + Base64.getEncoder().encodeToString(messageHash));
        System.out.println("B decode message: " + Base64.getEncoder().encodeToString(decodeSignature));
        System.out.println();

        if(MessageDigest.isEqual(messageHash, decodeSignature))
        {
            System.out.println("Verification success");
        } else {
            System.out.println("Verification failed");
        }
    }
}
