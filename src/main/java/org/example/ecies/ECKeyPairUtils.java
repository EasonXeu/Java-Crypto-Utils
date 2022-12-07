package org.example.ecies;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.example.EncodeUtils.base64Decode;
import static org.example.EncodeUtils.base64Encode;

public class ECKeyPairUtils {

    public static final String EC_ALGORITHM_NAME = "EC";
    public static final String CURVE = "secp256k1";
    public static final String TRANSFORMATION = "ECIES";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGenerator =
            KeyPairGenerator.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.initialize(new ECGenParameterSpec(CURVE));
        KeyPair keyPair = keyGenerator.generateKeyPair();
        System.out.println(keyPair.getPublic().toString());
        System.out.println(keyPair.getPrivate().toString());
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
}
