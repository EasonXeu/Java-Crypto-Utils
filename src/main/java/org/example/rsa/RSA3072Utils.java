package org.example.rsa;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.example.Base64Utils.decodeBase64String;
import static org.example.Base64Utils.encodeBase64String;

/**
 * 128-bit security strength
 */
public class RSA3072Utils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String RSA_ALGORITHM_NAME = "RSA";
    private static final int RSA_MODULE_SIZE = 3072;
    private static final String TRANSFORMATION = "RSA";

    public static String encrypt(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText);
        return encodeBase64String(encrypted);
    }

    public static byte[] decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(decodeBase64String(cipherText));
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.initialize(RSA_MODULE_SIZE);
        return keyGenerator.generateKeyPair();
    }

    public static String serializePublicKey(PublicKey publicKey) {
        return encodeBase64String(publicKey.getEncoded());
    }

    public static String serializePrivateKey(PrivateKey privateKey) {
        return encodeBase64String(privateKey.getEncoded());
    }

    public static PublicKey deserializePublicKey(String publicKeyString) throws Exception{
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(decodeBase64String(publicKeyString));
        return kf.generatePublic(keySpec);
    }

    public static PrivateKey deserializePrivateKey(String publicKeyString) throws Exception{
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodeBase64String(publicKeyString));
        return kf.generatePrivate(keySpec);
    }

}