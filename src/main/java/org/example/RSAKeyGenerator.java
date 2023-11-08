package org.example;

import lombok.Getter;
import lombok.extern.java.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

@Getter
@Log
public class RSAKeyGenerator {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSAKeyGenerator(int keyLength) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keyLength);
            var keypair = keyGen.genKeyPair();

            publicKey = keypair.getPublic();
            privateKey = keypair.getPrivate();
        } catch (Exception e) {
            log.info(e.getMessage());
        }
    }

    public void WriteToFile(String path, byte[] key){
        Objects.requireNonNull(path);
        try {
            var f = new File(path);
            var fos = new FileOutputStream(f);
            fos.write(key);
            fos.flush();
            fos.close();
        } catch (Exception e) {
            log.info(e.getMessage());
        }
    }
}
