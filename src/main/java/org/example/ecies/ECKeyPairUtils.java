package org.example.ecies;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.BigIntegers;
import static org.example.EncodeUtils.base64Decode;
import static org.example.EncodeUtils.base64Encode;

public class ECKeyPairUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final String EC_ALGORITHM_NAME = "EC";
    public static final String CURVE = "secp256k1";
    public static final String TRANSFORMATION = "ECIES";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGenerator =
            KeyPairGenerator.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.initialize(new ECGenParameterSpec(CURVE));
        KeyPair keyPair = keyGenerator.generateKeyPair();
        return keyPair;
    }

    public static String serializePublicKey(PublicKey publicKey) {
        return base64Encode(publicKey.getEncoded());
    }

    public static String serializePrivateKey(PrivateKey privateKey) {
        return base64Encode(privateKey.getEncoded());
    }

    public static PublicKey deserializePublicKey(String publicKeyString) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(base64Decode(publicKeyString));
        return kf.generatePublic(keySpec);
    }

    public static PrivateKey deserializePrivateKey(String publicKeyString) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(base64Decode(publicKeyString));
        return kf.generatePrivate(keySpec);
    }

    public static PublicKey deserializePublicKeyInBigIntFormat(String numGx, String numGy) throws Exception {
        BigInteger gx = new BigInteger(numGx, 10);
        BigInteger gy = new BigInteger(numGy, 10);
        ECPoint ecPoint = new ECPoint(gx, gy);
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECNamedCurveSpec params = new ECNamedCurveSpec(CURVE, spec.getCurve(), spec.getG(), spec.getN());
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, params);
        return kf.generatePublic(ecPublicKeySpec);
    }

    public static PrivateKey deserializePrivateKeyInBigIntFormat(String d) throws Exception {
        BigInteger k = new BigInteger(d, 10);
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(CURVE, spec.getCurve(), spec.getG(), spec.getN());
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(k, ecParameterSpec);
        return kf.generatePrivate(ecPrivateKeySpec);
    }

    // following is to store the key pair in bigint format
    public static byte[] serializePrivateKeyInBigIntFormat(BCECPrivateKey privateKey) throws Exception {
        return BigIntegers.asUnsignedByteArray(privateKey.getD());
    }

    public static byte[] serializePublicKeyInBigIntFormat(BCECPublicKey publicKey) throws Exception {
        return publicKey.getQ().getEncoded(false);
    }

    public static BCECPublicKey deserializePublicKeyInBigIntFormat(byte[] encodedPoint) throws Exception {
        BigInteger x = BigIntegers.fromUnsignedByteArray(encodedPoint, 1, 32);
        BigInteger y = BigIntegers.fromUnsignedByteArray(encodedPoint, 33, 32);

        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), getECNamedCurveSpec());
        return (BCECPublicKey) kf.generatePublic(ecPublicKeySpec);
    }

    public static BCECPublicKey deserializePublicKeyInBigIntFormat(byte[] px, byte[] py) throws Exception {
        BigInteger x = BigIntegers.fromUnsignedByteArray(px);
        BigInteger y = BigIntegers.fromUnsignedByteArray(py);

        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), getECNamedCurveSpec());
        return (BCECPublicKey) kf.generatePublic(ecPublicKeySpec);
    }

    public static BCECPrivateKey deserializePrivateKeyInBigIntFormat(byte[] d) throws Exception {
        BigInteger k = BigIntegers.fromUnsignedByteArray(d);
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(k, getECNamedCurveSpec());
        return (BCECPrivateKey) kf.generatePrivate(ecPrivateKeySpec);
    }

    public static ECNamedCurveSpec getECNamedCurveSpec() {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        return new ECNamedCurveSpec(CURVE, spec.getCurve(), spec.getG(), spec.getN());
    }

    public static void test() throws Exception {

    }

    public static void main(String[] args) throws Exception {
        test();
    }


}
