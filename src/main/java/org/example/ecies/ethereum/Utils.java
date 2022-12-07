package org.example.ecies.ethereum;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class Utils {

    private static final String CURVE_NAME = "secp256k1";
    private static final SecureRandom SECURE_RANDOM=new SecureRandom();


    public static ECDomainParameters getECDomainParameters() {
        final X9ECParameters params = SECNamedCurves.getByName(CURVE_NAME);
        return new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    public static ECCurve getCurve() {
        return getECDomainParameters().getCurve();
    }


    public static ECPoint getECPoint(BigInteger d){
        return new FixedPointCombMultiplier().multiply(getECDomainParameters().getG(), d);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.initialize(new ECGenParameterSpec(CURVE_NAME));
        KeyPair keyPair = keyGenerator.generateKeyPair();
        return keyPair;
    }

    public static byte[] randomBytes(int len) {
        byte[] bytes=new byte[len];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

}
