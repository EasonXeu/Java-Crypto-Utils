package org.example.ecies.common;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.example.EncodeUtils;
import org.example.ecies.custom.impl.AESGCMBlockCipher;

/**
 * 128-bit security strength
 */
public class CommonECIESUtils {

//    private static final byte[] NONCE = new byte[16];
//    private static final IESParameterSpec IES_PARAMETER_SPEC_FOR_AES_GCM =
//        new IESParameterSpec(null, null, 128, 128, Arrays.copyOfRange(NONCE, 0, 12));

    private static final IESParameterSpec IES_PARAMETER_SPEC_FOR_AES_CBC =
        new IESParameterSpec(null, null, 128, 128, null);

    public static String encrypt(byte[] plainText, BCECPublicKey publicKey) throws Exception {
        IESCipher cipher = getIESCipher();
        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, IES_PARAMETER_SPEC_FOR_AES_CBC, new SecureRandom());
        byte[] cipherResult = cipher.engineDoFinal(plainText, 0, plainText.length);
        return EncodeUtils.base64Encode(cipherResult);
    }

    public static byte[] decrypt(String cipherText, BCECPrivateKey privateKey) throws Exception {
        byte[] cipherBytes = EncodeUtils.base64Decode(cipherText);
        IESCipher cipher = getIESCipher();
        cipher.engineInit(Cipher.DECRYPT_MODE, privateKey, IES_PARAMETER_SPEC_FOR_AES_CBC, new SecureRandom());
        return cipher.engineDoFinal(cipherBytes, 0, cipherBytes.length);
    }

    private static IESCipher getIESCipher() {
//        return getIESCipherWithAESGCM();
        return getIESCipherWithAESCBC();
    }

    private static IESCipher getIESCipherWithAESCBC() {
        IESCipher cipher = new IESCipher(
            new IESEngine(
                new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA256Digest()),
                new HMac(DigestFactory.createSHA256()),
                new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding())), 0);
        return cipher;
    }

    // If we use this cipher, wer have to include the IV in the IESParameterSpec
    private static IESCipher getIESCipherWithAESGCM() {
        IESCipher cipher = new IESCipher(
            new IESEngine(
                new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA256Digest()),
                new HMac(DigestFactory.createSHA256()),
                new AESGCMBlockCipher()), 12);
        return cipher;
    }

}