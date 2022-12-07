package org.example.ecies.basic;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.example.EncodeUtils.base64Encode;
import org.example.ecies.ECKeyPairUtils;

public class App {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String msg = "Hello world";
        KeyPair keyPair = ECKeyPairUtils.generateKeyPair();
        // serialize key and store them
        String publicKeyString = ECKeyPairUtils.serializePublicKey(keyPair.getPublic());
        String privateKeyString = ECKeyPairUtils.serializePrivateKey(keyPair.getPrivate());
        System.out.printf("PublicKey: %s \n", publicKeyString);
        System.out.printf("PrivateKey: %s \n", privateKeyString);

        // deserialize key and use them
        PublicKey publicKey = ECKeyPairUtils.deserializePublicKey(publicKeyString);
        PrivateKey privateKey = ECKeyPairUtils.deserializePrivateKey(privateKeyString);

        String cipherText = BasicECIESUtils.encrypt(msg.getBytes(StandardCharsets.UTF_8), publicKey);
        System.out.println(cipherText);
        String plainMsg = new String(BasicECIESUtils.decrypt(cipherText, privateKey), StandardCharsets.UTF_8);
        System.out.println(plainMsg.equals(msg));
        System.out.println(plainMsg);

        System.out.printf("%s - %s", base64Encode(msg.getBytes()).length(), cipherText.length());
    }

}
