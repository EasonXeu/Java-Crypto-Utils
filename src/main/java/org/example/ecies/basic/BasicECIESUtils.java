package org.example.ecies.basic;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.example.EncodeUtils.base64Decode;
import static org.example.EncodeUtils.base64Encode;

/**
 * 128-bit security strength
 */
public class BasicECIESUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String TRANSFORMATION = "ECIES";

    public static String encrypt(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText);
        return base64Encode(encryptedBytes);
    }

    public static byte[] decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(base64Decode(cipherText));
    }

}