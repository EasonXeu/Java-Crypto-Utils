package org.example.ecies.custom;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.example.EncodeUtils;
import org.example.ecies.custom.impl.AESGCMBlockCipher;
import org.example.ecies.custom.impl.IESCipherGCM;
import org.example.ecies.custom.impl.IESEngineGCM;

/**
 * 128-bit security strength
 */
public class CustomECIESUtils {

    private static final IESParameterSpec IES_PARAMETER_SPEC = new IESParameterSpec(null, null, 128, 128, null);

    public static String encrypt(byte[] plaintext, BCECPublicKey publicKey) throws Exception {
        IESCipherGCM cipher = getIESCipherGCM();
        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, IES_PARAMETER_SPEC, new SecureRandom());
        byte[] cipherResult = cipher.engineDoFinal(plaintext, 0, plaintext.length);
        return Base64.toBase64String(cipherResult);
    }


    public static byte[] decrypt(String ciphertext, BCECPrivateKey privateKey) throws Exception {
        byte[] inputBytes = EncodeUtils.base64Decode(ciphertext);
        IESCipherGCM cipher = getIESCipherGCM();
        cipher.engineInit(Cipher.DECRYPT_MODE, privateKey, IES_PARAMETER_SPEC, new SecureRandom());
        return cipher.engineDoFinal(inputBytes, 0, inputBytes.length);
    }

    private static IESCipherGCM getIESCipherGCM() throws Exception {
        IESCipherGCM cipher = new IESCipherGCM(
            new IESEngineGCM(
                new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA256Digest()),
                new AESGCMBlockCipher()), 16);
        return cipher;
    }

}