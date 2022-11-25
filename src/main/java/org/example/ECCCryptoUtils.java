package org.example;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCCryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String EC_ALGORITHM_NAME = "EC";
    private static final String EC_GEN_PARAMETER_SPEC_NAME = "secp256k1";
    private static final String TRANSFORMATION = "ECIES";

    public static String encrypt(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText);
        return encodeBase64String(encryptedBytes);
    }

    public static byte[] decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(decodeBase64String(cipherText));
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.initialize(new ECGenParameterSpec(EC_GEN_PARAMETER_SPEC_NAME));
        return keyGenerator.generateKeyPair();
    }

    public static String serializePublicKey(PublicKey publicKey) {
        return encodeBase64String(publicKey.getEncoded());
    }

    public static String serializePrivateKey(PrivateKey privateKey) {
        return encodeBase64String(privateKey.getEncoded());
    }

    public static PublicKey deserializePublicKey(String publicKeyString) throws Exception{
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(decodeBase64String(publicKeyString));
        return kf.generatePublic(keySpec);
    }

    public static PrivateKey deserializePrivateKey(String publicKeyString) throws Exception{
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodeBase64String(publicKeyString));
        return kf.generatePrivate(keySpec);
    }

    public static String encodeBase64String(byte[] data) {
        return Base64.encodeBase64String(data);
    }

    public static byte[] decodeBase64String(String data) {
        return Base64.decodeBase64(data);
    }

    public static void main(String[] args) throws Exception {
        String msg = "Hello world";
        KeyPair keyPair = generateKeyPair();

        // serialize key and store them
        String publicKeyString = serializePublicKey(keyPair.getPublic());
        String privateKeyString = serializePrivateKey(keyPair.getPrivate());
        System.out.printf("PublicKey: %s \n", publicKeyString);
        System.out.printf("PrivateKey: %s \n",privateKeyString);

        // deserialize key and use them
        PublicKey publicKey = deserializePublicKey(publicKeyString);
        PrivateKey privateKey = deserializePrivateKey(privateKeyString);

        String cipherText = encrypt(msg.getBytes(StandardCharsets.UTF_8), publicKey);
        System.out.println(cipherText);
        String plainMsg = new String(decrypt(cipherText, privateKey), StandardCharsets.UTF_8);
        System.out.println(plainMsg.equals(msg));

        System.out.printf("%s - %s", encodeBase64String(msg.getBytes()).length(), cipherText.length());
    }
}