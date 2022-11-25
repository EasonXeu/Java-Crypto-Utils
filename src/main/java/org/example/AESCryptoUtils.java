package org.example;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESCryptoUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final String AES_ALGORITHM_NAME = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static SecretKey generateKey(int n) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(byte[] plainText, SecretKey key, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText);
        return Base64.encodeBase64String(encryptedBytes);
    }

    public static byte[] decrypt(String cipherText, SecretKey key,  IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        byte[] cipherData = Base64.decodeBase64(cipherText);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(cipherData);
    }

    public static void main(String[] args) throws Exception {
        String msg = "Hello world";
        SecretKey key = generateKey(128);
        IvParameterSpec ivParameterSpec = generateIv();
        String cipherText = encrypt(msg.getBytes(StandardCharsets.UTF_8),key,ivParameterSpec);
        System.out.println(cipherText);
        String plainMsg = new String(decrypt(cipherText, key,ivParameterSpec), StandardCharsets.UTF_8);
        System.out.println(plainMsg.equals(msg));
        System.out.printf("%s - %s", Base64.encodeBase64String(msg.getBytes()).length(), cipherText.length());
    }

}

