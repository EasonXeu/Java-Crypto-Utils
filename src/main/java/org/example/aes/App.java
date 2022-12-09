package org.example.aes;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Base64;
import org.example.EncodeUtils;

public class App {
    public static void main(String[] args) throws Exception {
        String msg = "Hello world";
        SecretKey key = AES128Utils.generateKey(128);
        System.out.println("Key:" + EncodeUtils.base64Encode(key.getEncoded()));
        IvParameterSpec ivParameterSpec = AES128Utils.generateIvParamSpec();
        String cipherText = AES128Utils.encrypt(msg.getBytes(StandardCharsets.UTF_8), key, ivParameterSpec);
        System.out.println(cipherText);
        String plainMsg = new String(AES128Utils.decrypt(cipherText, key, ivParameterSpec), StandardCharsets.UTF_8);
        System.out.println(plainMsg.equals(msg));
        System.out.printf("%s - %s", Base64.encodeBase64String(msg.getBytes()).length(), cipherText.length());
    }

}
