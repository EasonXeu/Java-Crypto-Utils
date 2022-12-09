package org.example.aes;

import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.example.EncodeUtils.base64Decode;
import static org.example.EncodeUtils.base64Encode;

/**
 * 128-bit security strength
 */
public class AES128Utils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String AES_ALGORITHM_NAME = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS7Padding";

    public static SecretKey generateKey(int n) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec generateIvParamSpec() {
        byte[] iv = generateIv();
        return new IvParameterSpec(iv);
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[16];
//        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String encrypt(byte[] plainText, SecretKey key, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText);
        return base64Encode(encryptedBytes);
    }

    public static byte[] decrypt(String cipherText, SecretKey key, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        byte[] cipherData = base64Decode(cipherText);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(cipherData);
    }

}

