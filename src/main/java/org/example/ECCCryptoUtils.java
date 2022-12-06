package org.example;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCStagedAgreement;
import org.bouncycastle.crypto.agreement.ECDHCUnifiedAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.engines.OldIESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;


public class ECCCryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String EC_ALGORITHM_NAME = "EC";
    private static final String CURVE = "secp256k1";
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

    public static PublicKey deserializePublicKeyFromNumber(String numGx,String numGy) throws Exception{
        BigInteger gx = new BigInteger(numGx);
        BigInteger gy = new BigInteger(numGy);
        ECPoint ecPoint=new ECPoint(gx, gy);

        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECNamedCurveSpec params = new ECNamedCurveSpec(CURVE, spec.getCurve(), spec.getG(), spec.getN());
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint,params);
        return kf.generatePublic(ecPublicKeySpec);
    }

    public static PrivateKey deserializePrivateKeyFromNumber(String d) throws Exception{
        BigInteger k = new BigInteger(d);
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(CURVE, spec.getCurve(),spec.getG(),spec.getN());
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(k,ecParameterSpec);
        return kf.generatePrivate(ecPrivateKeySpec);
    }

    public static String encodeBase64String(byte[] data) {
        return Base64.encodeBase64String(data);
    }

    public static byte[] decodeBase64String(String data) {
        return Base64.decodeBase64(data);
    }

    private static void test1(String msg) throws Exception {
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

    private static void test2(String cipherText) throws Exception {

        PublicKey publicKey = deserializePublicKeyFromNumber(
            "",
            "");

        PrivateKey privateKey = deserializePrivateKeyFromNumber(
            "");

        String plainMsg = new String(decrypt(cipherText, privateKey), StandardCharsets.UTF_8);
        System.out.println(plainMsg);

        System.out.printf("%s - %s", plainMsg.length(), cipherText.length());
    }

    public static void main(String[] args) throws Exception {
        String msg = "Hello world";
        test1(msg);
        test2("BI8Tjc566267CMs/w4oqcE4am6mlLS+rg4rEmo0xY7499PDcRcMo05MV0CU3PAYpRQcZU4KAqSVsqGvGiZaPY5GzBqFPBTmS0m+GXcwIoR7PDu/7oa+7XTby+L3kUEbjxLi8C1ezpLCBOMaNUKz+CIJ1EVKfK3SevbLz5g");
    }
}