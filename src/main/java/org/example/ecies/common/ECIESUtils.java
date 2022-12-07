package org.example.ecies.common;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
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
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIESwithSHA256andAESCBC;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.example.Base64Utils.decodeBase64String;
import static org.example.Base64Utils.encodeBase64String;

/**
 * 128-bit security strength
 */
public class ECIESUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String EC_ALGORITHM_NAME = "EC";
    private static final String CURVE = "secp256k1";
    private static final String TRANSFORMATION = "ECIES";

    public static String encrypt(byte[] plainText, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, getAlgorithmParameters());
        byte[] encryptedBytes = cipher.doFinal(plainText);
        return encodeBase64String(encryptedBytes);
    }

    public static byte[] decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        ECIESwithSHA256andAESCBC ecieSwithSHA256andAESCBC = new ECIESwithSHA256andAESCBC();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, getAlgorithmParameters());
        return cipher.doFinal(decodeBase64String(cipherText));
    }

    private static AlgorithmParameters getAlgorithmParameters() {
        ECIESwithSHA256andAESCBC ecieSwithSHA256andAESCBC = new ECIESwithSHA256andAESCBC();
        AlgorithmParameters algorithmParameters = ecieSwithSHA256andAESCBC.engineGetParameters();
        return algorithmParameters;
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.initialize(new ECGenParameterSpec(CURVE));
        KeyPair keyPair = keyGenerator.generateKeyPair();
        System.out.println(keyPair.getPublic().toString());
        System.out.println(keyPair.getPrivate().toString());
        return keyPair;
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
}