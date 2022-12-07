package org.example.rsa;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class App {

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = RSA3072Utils.generateKeyPair();

        String msg = "Hello world";
        // serialize key and store them
        String publicKeyString = RSA3072Utils.serializePublicKey(keyPair.getPublic());
        String privateKeyString = RSA3072Utils.serializePrivateKey(keyPair.getPrivate());
        // deserialize key and use them
        PublicKey publicKey = RSA3072Utils.deserializePublicKey(publicKeyString);
        PrivateKey privateKey = RSA3072Utils.deserializePrivateKey(privateKeyString);

        String cipherText = RSA3072Utils.encrypt(msg.getBytes(StandardCharsets.UTF_8), publicKey);
        String plainMsg = new String(RSA3072Utils.decrypt(cipherText, privateKey), StandardCharsets.UTF_8);
        System.out.println(plainMsg.equals(msg));
    }

}
