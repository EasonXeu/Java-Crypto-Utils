package org.example.ecies.ethereum;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.Base64Utils;

public class Main {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static final void main(String[] args) throws Exception {
//        {
//            KeyPair keyPair = Utils.generateKeyPair();
//            ECIESEncryptionEngine engine = ECIESEncryptionEngine.forEncryption((BCECPublicKey) keyPair.getPublic());
//            String msg = "Hello_world";
//            byte[] emsg = engine.encrypt(msg.getBytes());
//            System.out.println(Base64Utils.encodeBase64String(emsg));
//            System.out.println(new String(engine.decrypt(emsg)));
//        }
        {
//            KeyPair keyPair = Utils.generateKeyPair();
            BigInteger d = new BigInteger("31982473480693604137567984429316334185194099694227245800857878042731418965199",10);
            BigInteger x = new BigInteger("43897316013411965786723251129779756335242873880606845541021343506782702582565",10);
            BigInteger y = new BigInteger("28852353217654674961362744253253946541791143465170087599610159217644641234975", 10);
            BCECPrivateKey privateKey = ECIESUtils.deserializePrivateKeyFromNumber(d);
            BCECPublicKey publicKey = ECIESUtils.deserializePublicKeyFromNumber(x,y);
            ECIESUtils eciesUtils = new ECIESUtils();
            String msg = "BI8Tjc566267CMs/w4oqcE4am6mlLS+rg4rEmo0xY7499PDcRcMo05MV0CU3PAYpRQcZU4KAqSVsqGvGiZaPY5GzBqFPBTmS0m+GXcwIoR7PDu/7oa+7XTby+L3kUEbjxLi8C1ezpLCBOMaNUKz+CIJ1EVKfK3SevbLz5g";
            byte[] emsg = eciesUtils.decrypt(Base64Utils.decodeBase64String(msg), privateKey);
            System.out.println(new String(emsg));
            System.out.println(Base64Utils.encodeBase64String(emsg));
//            System.out.println(new String(eciesUtils.decrypt(emsg)));
        }



    }
}
