package org.example.ecies.ethereum;

import static com.google.common.base.Preconditions.checkArgument;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.example.Base64Utils;

public class ECIESUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final byte[] IES_DERIVATION = new byte[0];
    private static final byte[] IES_ENCODING = new byte[0];
    private static final short CIPHER_BLOCK_SIZE = 16;
    private static final short CIPHER_KEY_SIZE_BITS = CIPHER_BLOCK_SIZE * 8;
    private static final short MAC_KEY_SIZE = 32;

    private static final IESWithCipherParameters PARAM = new IESWithCipherParameters(IES_DERIVATION, IES_ENCODING, CIPHER_KEY_SIZE_BITS, CIPHER_KEY_SIZE_BITS);
    private static final int CIPHER_KEY_SIZE = PARAM.getCipherKeySize();
    private static final int CIPHER_MAC_KEY_SIZE = PARAM.getMacKeySize();

    // Configure the components of the Integrated Encryption Scheme.
    private final Digest hash = new SHA256Digest();
    private final DerivationFunction kdf = new ECIESHandshakeKDFFunction();
    private final HMac mac = new HMac(new SHA256Digest());
    private final BufferedBlockCipher cipher = new BufferedBlockCipher(new SICBlockCipher(new AESEngine()));

    // TODO: This V is possibly redundant.
    private final byte[] V = new byte[0];
    private final byte[] iv = Base64Utils.decodeHexString("bc90acc06fb5e2f395ab0af7694ac136");

    public byte[] encrypt(final byte[] in, BCECPublicKey publicKey) throws Exception {
        return encrypt(in, 0, in.length, null, publicKey);
    }

    private byte[] encrypt(byte[] in, int inOff, int inLen, byte[] macData, BCECPublicKey publicKey) throws Exception{
        KeyPair ephemeralKeyPair = Utils.generateKeyPair();
        BCECPublicKey ephemeralPublicKey = (BCECPublicKey) ephemeralKeyPair.getPublic();
        BCECPrivateKey ephemeralPrivateKey = (BCECPrivateKey) ephemeralKeyPair.getPrivate();
        System.out.println(ephemeralPublicKey.getQ().toString());
        System.out.println(ephemeralPrivateKey.getD().toString());
        // Create parameters.
        CipherParameters pubParam = new ECPublicKeyParameters(publicKey.getQ(), Utils.getECDomainParameters());
        final CipherParameters ephemeralPrivateKeyParams = new ECPrivateKeyParameters(ephemeralPrivateKey.getD(), Utils.getECDomainParameters());

        final BasicAgreement agree = new ECDHBasicAgreement();
        agree.init(ephemeralPrivateKeyParams);
        final BigInteger z = agree.calculateAgreement(pubParam);
        final byte[] Z = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);
        // Initialise the KDF.
        this.kdf.init(new KDFParameters(Z, PARAM.getDerivationV()));

        // Block cipher mode.
        byte[] K1 = new byte[CIPHER_KEY_SIZE / 8];
        byte[] K2 = new byte[CIPHER_MAC_KEY_SIZE / 8];
        byte[] K  = new byte[K1.length + K2.length];


        kdf.generateBytes(K, 0, K.length);
        System.arraycopy(K, 0, K1, 0, K1.length);
        System.arraycopy(K, K1.length, K2, 0, K2.length);

        // Initialize the cipher with the IV.
        cipher.init(true, new ParametersWithIV(new KeyParameter(K1), iv));
        byte[] C = new byte[cipher.getOutputSize(inLen)];
        int len = cipher.processBytes(in, inOff, inLen, C, 0);
        len = len + cipher.doFinal(C, len);

        // Convert the length of the encoding vector into a byte array.
        final byte[] P2 = PARAM.getEncodingV();

        // Apply the MAC.
        final byte[] T = new byte[mac.getMacSize()];

        final byte[] K2hash = new byte[hash.getDigestSize()];
        hash.reset();
        hash.update(K2, 0, K2.length);
        hash.doFinal(K2hash, 0);

        mac.init(new KeyParameter(K2hash));
        mac.update(iv, 0, iv.length);
        mac.update(C, 0, C.length);

        if (P2 != null) {
            mac.update(P2, 0, P2.length);
        }

        if (V.length != 0 && P2 != null) {
            final byte[] L2 = Pack.intToBigEndian(P2.length * 8);
            mac.update(L2, 0, L2.length);
        }

        if (macData != null) {
            mac.update(macData, 0, macData.length);
        }

        mac.doFinal(T, 0);

        // Output the triple (V,C,T).
        final byte[] Output = new byte[V.length + len + T.length];
        System.arraycopy(V, 0, Output, 0, V.length);
        System.arraycopy(C, 0, Output, V.length, len);
        System.arraycopy(T, 0, Output, V.length + len, T.length);
        return Output;
    }


    public byte[] decrypt(final byte[] in, BCECPrivateKey privateKey) throws Exception {
        return decrypt(in, 0, in.length, null, privateKey);
    }


    private byte[] decrypt(byte[] inEnc, int inOff, int inLen, byte[] commonMac, BCECPrivateKey privateKey) throws Exception {
        if (inEnc == null || inEnc.length==0) {
            throw new InvalidCipherTextException("invalid enc message");
        }
        byte flag = inEnc[0];
        if (flag!=2 && flag!=3 && flag!=4){
            throw new InvalidCipherTextException("invalid enc message");
        }
        int rLen = (privateKey.getParameters().getCurve().getFieldSize() + 7) / 4;
        byte[] ephemeralPublicKeyBytes = Arrays.copyOfRange(inEnc,0, rLen);

        BigInteger[] ephemeralPublicKeyPoint = unmarshal(ephemeralPublicKeyBytes);
        BCECPublicKey ephemeralPublicKey = deserializePublicKeyFromNumber(ephemeralPublicKeyPoint[0],ephemeralPublicKeyPoint[1]);

        BasicAgreement agree = new ECDHBasicAgreement();
        agree.init(new ECPrivateKeyParameters(privateKey.getD(), Utils.getECDomainParameters()));
        final BigInteger z = agree.calculateAgreement(new ECPublicKeyParameters(ephemeralPublicKey.getQ(), Utils.getECDomainParameters()));
        byte[] shared = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);

        final byte[] M;
        int len;

        // Ensure that the length of the input is greater than the MAC in bytes
        if (inLen <= (CIPHER_MAC_KEY_SIZE / 8)) {
            throw new InvalidCipherTextException("Length of input must be greater than the MAC");
        }

        SHA256Digest sha256Digest = new SHA256Digest();
        // Block cipher mode.
        byte[] ke = new byte[CIPHER_KEY_SIZE / 8];
        byte[] km = new byte[CIPHER_MAC_KEY_SIZE / 8];
        byte[] k = new byte[sha256Digest.getDigestSize()];
        ConcatenationKDFGenerator kdf=new ConcatenationKDFGenerator(sha256Digest);
        KDFParameters kdfParameters=new KDFParameters(shared, V);
        kdf.init(kdfParameters);
        kdf.generateBytes(k, 0, k.length);
        System.arraycopy(k, 0, ke, 0, ke.length);
        System.arraycopy(k, ke.length, km, 0, km.length);

        km = sha256(km);

        int macLen = MAC_KEY_SIZE;
        byte[] macBytes = Arrays.copyOfRange(inEnc, inLen-macLen, inLen);
        byte[] cBytes = Arrays.copyOfRange(inEnc, rLen,inLen-macLen);

        byte[] destMacBytes = hmacSha256(cBytes, km);

        if (!Arrays.constantTimeAreEqual(destMacBytes, macBytes)) {
            throw new InvalidCipherTextException("Invalid MAC.");
        }

        //Decrypt the message
        byte[] iv = new byte[CIPHER_BLOCK_SIZE];
        System.arraycopy(cBytes,0,iv,0,iv.length);

        byte[] msg = symmetricDecrypt(ke,iv,cBytes);

        // Output the message.
        return msg;
    }

    private static byte[] sha256(byte[] message) throws Exception {
        SHA256Digest sha256Digest = new SHA256Digest();
        byte[] data = new byte[sha256Digest.getDigestSize()];
        sha256Digest.reset();
        sha256Digest.update(message,0, message.length);
        sha256Digest.doFinal(data,0);
        return data;
    }

    private static byte[] hmacSha256(byte[] message, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256", "BC");
        mac.init(secretKey);
        mac.update(message);
        return mac.doFinal();
    }

    private static byte[] symmetricDecrypt(byte[] key, byte[] iv, byte[] msg) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(msg);
    }

    /**
     * Key generation function as defined in NIST SP 800-56A, but swapping the order of the digested
     * values (counter first, shared secret second) to comply with Ethereum's approach.
     *
     * <p>This class has been adapted from the <code>BaseKDFBytesGenerator</code> implementation of
     * Bouncy Castle.
     */
    private static class ECIESHandshakeKDFFunction implements DigestDerivationFunction {
        private static final int COUNTER_START = 1;
        private final Digest digest = new SHA256Digest();
        private final int digestSize = digest.getDigestSize();
        private byte[] shared;
        private byte[] iv;

        @Override
        public void init(final DerivationParameters param) {
            checkArgument(param instanceof KDFParameters, "unexpected expected KDF params type");

            final KDFParameters p = (KDFParameters) param;
            shared = p.getSharedSecret();
            iv = p.getIV();
        }

        /**
         * Returns the underlying digest.
         *
         * @return The digest.
         */
        @Override
        public Digest getDigest() {
            return digest;
        }

        /**
         * Fills <code>len</code> bytes of the output buffer with bytes generated from the derivation
         * function.
         *
         * @throws IllegalArgumentException If the size of the request will cause an overflow.
         * @throws DataLengthException      If the out buffer is too small.
         */
        @Override
        public int generateBytes(final byte[] out, final int outOff, final int len)
            throws DataLengthException, IllegalArgumentException {
            checkArgument(len >= 0, "length to fill cannot be negative");

            if ((out.length - len) < outOff) {
                throw new DataLengthException("output buffer too small");
            }

            final int outLen = digest.getDigestSize();
            final int cThreshold = (len + outLen - 1) / outLen;
            final byte[] dig = new byte[digestSize];
            final byte[] C = Pack.intToBigEndian(COUNTER_START);
            int counterBase = COUNTER_START & ~0xFF;
            int offset = outOff;
            int length = len;

            for (int i = 0; i < cThreshold; i++) {
                // Ethereum peculiarity: Ethereum requires digesting the counter and the shared secret is
                // inverse order
                // that of the standard BaseKDFBytesGenerator in Bouncy Castle.
                digest.update(C, 0, C.length);
                digest.update(shared, 0, shared.length);

                if (iv != null) {
                    digest.update(iv, 0, iv.length);
                }

                digest.doFinal(dig, 0);

                if (length > outLen) {
                    System.arraycopy(dig, 0, out, offset, outLen);
                    offset += outLen;
                    length -= outLen;
                } else {
                    System.arraycopy(dig, 0, out, offset, length);
                }

                if (++C[3] == 0) {
                    counterBase += 0x100;
                    Pack.intToBigEndian(counterBase, C, 0);
                }
            }

            digest.reset();
            return length;
        }
    }
    private static final String EC_ALGORITHM_NAME = "EC";
    private static final String CURVE = "secp256k1";

    public static BCECPublicKey deserializePublicKeyFromNumber(BigInteger x, BigInteger y) throws Exception{
        ECPoint ecPoint=new ECPoint(x, y);
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECNamedCurveSpec params = new ECNamedCurveSpec(CURVE, spec.getCurve(), spec.getG(), spec.getN());
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint,params);
        return (BCECPublicKey) kf.generatePublic(ecPublicKeySpec);
    }

    public static BCECPrivateKey deserializePrivateKeyFromNumber(BigInteger d) throws Exception{
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(CURVE, spec.getCurve(),spec.getG(),spec.getN());
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d,ecParameterSpec);
        return (BCECPrivateKey) kf.generatePrivate(ecPrivateKeySpec);
    }

    /**
     * Unmarshall Curve Point
     * @param data
     * @return
     * @throws InvalidCipherTextException
     */
    public static BigInteger[] unmarshal(byte[] data) throws InvalidCipherTextException {
//        return ECIESPublicKeyParser()
        int rLen = (Utils.getCurve().getFieldSize() + 7) / 8;
        if(rLen * 2 +1 != data.length){
            throw new InvalidCipherTextException("invalid enc message");
        }
        BigInteger x = BigIntegers.fromUnsignedByteArray(data,1,rLen);
        BigInteger y = BigIntegers.fromUnsignedByteArray(data, rLen+1,rLen);
        return new BigInteger[]{x,y};
    }

    /**
     * Marshall Curve Point
     * @param x
     * @param y
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] marshal(BigInteger x, BigInteger y) throws InvalidCipherTextException {
        int rLen = (Utils.getCurve().getFieldSize() + 7) / 8;
        byte[] xb = x.toByteArray();
        byte[] yb = x.toByteArray();
        if(rLen!=xb.length || rLen!=yb.length){
            throw new InvalidCipherTextException("invalid enc message");
        }
        byte[] data = new byte[rLen*2+1];
        data[0] = 4;
        System.arraycopy(xb,0,data,1,rLen);
        System.arraycopy(yb,0,data,1+rLen,2*rLen+1);
        return data;
    }
}
