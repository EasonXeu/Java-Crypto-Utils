package org.example.ecies.common;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import static org.example.Base64Utils.encodeBase64String;

public class App {

    public static void main(String[] args) throws Exception {
        String msg = "Hello world";
        KeyPair keyPair = ECIESUtils.generateKeyPair();
        // serialize key and store them
        String publicKeyString = ECIESUtils.serializePublicKey(keyPair.getPublic());
        String privateKeyString = ECIESUtils.serializePrivateKey(keyPair.getPrivate());
        System.out.printf("PublicKey: %s \n", publicKeyString);
        System.out.printf("PrivateKey: %s \n", privateKeyString);

        // deserialize key and use them
        PublicKey publicKey = ECIESUtils.deserializePublicKey(publicKeyString);
        PrivateKey privateKey = ECIESUtils.deserializePrivateKey(privateKeyString);

        String cipherText = ECIESUtils.encrypt(msg.getBytes(StandardCharsets.UTF_8), publicKey);
        System.out.println(cipherText);
        String plainMsg = new String(ECIESUtils.decrypt(cipherText, privateKey), StandardCharsets.UTF_8);
        System.out.println(plainMsg.equals(msg));

        System.out.printf("%s - %s", encodeBase64String(msg.getBytes()).length(), cipherText.length());
    }

}
