package org.example.ecies.todo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.example.EncodeUtils;


public class ECCCryptoUtils1 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String EC_ALGORITHM_NAME = "EC";
    private static final String CURVE = "secp256k1";
    private static final String TRANSFORMATION = "ECIES";

    public static String encrypt(byte[] plainText, PublicKey publicKey) throws Exception {
//        ECDomainParameters ecParams = ((ECKeyParameters)publicKey).getParameters();
//        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(plainText);
//
//        EphemeralKeyPair ephKeyPair = getEphemeralKeyPairGenerator(ecParams);
//        AsymmetricKeyParameter privParam = ephKeyPair.getKeyPair().getPrivate();
//        byte[] V = ephKeyPair.getEncodedPublicKey();
//
//        AsymmetricKeyParameter pubParam = new ECIESPublicKeyParser(ecParams).readKey(byteArrayInputStream);
//        ECDHCUnifiedAgreement agree=new ECDHCUnifiedAgreement();
//        agree.init(privParam);
//        byte[] z = agree.calculateAgreement(pubParam);
//        System.out.println(z);
//
//        byte[][] keys = generateSharedKey(z);
//        byte[] ke = keys[0];
//        byte[] km = keys[1];
//
//        GCMBlockCipher cipher=new G


//        // Encrypt the buffer
//        try
//        {
//            engine.init(key, params, kGen);
//
//            return engine.processBlock(in, 0, in.length);
//        }
//        catch (final Exception e)
//        {
//            throw new BadBlockException("unable to process block", e);
//        }
        return null;
    }

    private static EphemeralKeyPair getEphemeralKeyPairGenerator(ECDomainParameters ecParams) {
        // Generate the ephemeral key pair
        SecureRandom secureRandom = new SecureRandom();
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ecParams, secureRandom));
        EphemeralKeyPairGenerator kGen = new EphemeralKeyPairGenerator(gen, new KeyEncoder() {
            public byte[] getEncoded(AsymmetricKeyParameter keyParameter) {
                return ((ECPublicKeyParameters) keyParameter).getQ().getEncoded(false);
            }
        });
        return kGen.generate();
    }

    private static byte[][] generateSharedKey(byte[] secret) throws NoSuchAlgorithmException {
        ConcatenationKDFGenerator kdf = new ConcatenationKDFGenerator(DigestFactory.createSHA256());
        return getSharedSecretBytes(kdf, secret, null, secret.length * 8);
    }


    private static byte[][] getSharedSecretBytes(ConcatenationKDFGenerator kdf, byte[] secret, String oidAlgorithm,
                                                 int keySize)
        throws NoSuchAlgorithmException {
        if (keySize < 0) {
            throw new NoSuchAlgorithmException("unknown algorithm encountered: " + oidAlgorithm);
        }
        byte[] k1 = new byte[keySize / 8];
        byte[] k2 = new byte[keySize / 8];
        byte[] k = new byte[k1.length + k2.length];
        KDFParameters params = new KDFParameters(secret, null);
        kdf.init(params);
        kdf.generateBytes(k, 0, k.length);
        System.arraycopy(k, 0, k1, 0, k1.length);
        System.arraycopy(k, k1.length, k2, 0, k2.length);
        byte[][] data = {k1, k2};
        return data;

    }

    public static byte[] decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        IESParameterSpec parameterSpec = new IESParameterSpec(null, null, 16, 16, nonce, false);
        IESEngine iesEngine = new IESEngine(new ECDHBasicAgreement(),
            new ConcatenationKDFGenerator(DigestFactory.createSHA256()),
            new HMac(DigestFactory.createSHA256()),
            new PaddedBufferedBlockCipher(new AESEngine()));
        byte[] msg = EncodeUtils.base64Decode(cipherText);
        IESCipher iesCipher = new IESCipher(iesEngine, 16);
        iesCipher.engineInit(Cipher.DECRYPT_MODE, privateKey, parameterSpec, new SecureRandom());
        return iesCipher.engineDoFinal(msg, 0, msg.length);
    }


    public static PublicKey deserializePublicKeyFromNumber(String numGx, String numGy) throws Exception {
        BigInteger gx = new BigInteger(numGx);
        BigInteger gy = new BigInteger(numGy);
        ECPoint ecPoint = new ECPoint(gx, gy);

        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECNamedCurveSpec params = new ECNamedCurveSpec(CURVE, spec.getCurve(), spec.getG(), spec.getN());
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, params);
        return kf.generatePublic(ecPublicKeySpec);
    }

    public static PrivateKey deserializePrivateKeyFromNumber(String d) throws Exception {
        BigInteger k = new BigInteger(d);
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(CURVE, spec.getCurve(), spec.getG(), spec.getN());
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(k, ecParameterSpec);
        return kf.generatePrivate(ecPrivateKeySpec);
    }


    private static void test2(String cipherText) throws Exception {

//        PublicKey publicKey = deserializePublicKeyFromNumber(
//            "",
//            "");

        PrivateKey privateKey = deserializePrivateKeyFromNumber(
            "31982473480693604137567984429316334185194099694227245800857878042731418965199");

        String plainMsg = new String(decrypt(cipherText, privateKey), StandardCharsets.UTF_8);
        System.out.println(plainMsg);

        System.out.printf("%s - %s", plainMsg.length(), cipherText.length());
    }

    public static void main(String[] args) throws Exception {
        test2(
            "BI8Tjc566267CMs/w4oqcE4am6mlLS+rg4rEmo0xY7499PDcRcMo05MV0CU3PAYpRQcZU4KAqSVsqGvGiZaPY5GzBqFPBTmS0m+GXcwIoR7PDu/7oa+7XTby+L3kUEbjxLi8C1ezpLCBOMaNUKz+CIJ1EVKfK3SevbLz5g");
    }
}