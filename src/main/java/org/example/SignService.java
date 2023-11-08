package org.example;
import lombok.extern.java.Log;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

@Log
public class SignService {
    private Cipher cipher;
    private final String algorithm = "RSA";

    public enum KeyTypes {
        Private,
        Public
    }

    public Key loadKey(String path, KeyTypes keyTypes) throws Exception {
        Objects.requireNonNull(path);

        var keyBytes    = Files.readAllBytes(new File(path).toPath());
        var keyFactory  = KeyFactory.getInstance(algorithm);

        switch (keyTypes) {
            case Private -> {
                var keySpec = new PKCS8EncodedKeySpec(keyBytes);
                return keyFactory.generatePrivate(keySpec);
            }
            case Public -> {
                var keySpec = new X509EncodedKeySpec(keyBytes);
                return keyFactory.generatePublic(keySpec);
            }
        }

        return null;
    }

    public byte[] encryptText(byte[] msg, PrivateKey key) throws Exception {
        cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encode(cipher.doFinal(msg));
    }

    public byte[] decryptText(byte[] msg, PublicKey key) throws Exception {
        cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(Base64.getDecoder().decode(msg));
    }
}
