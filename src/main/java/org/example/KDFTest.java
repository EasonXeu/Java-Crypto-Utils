package org.example;

import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.util.DigestFactory;

public class KDFTest {
    public static void main(String[] args) {
        Digest sha256 = DigestFactory.createSHA1();
        KDF2BytesGenerator kdf2BytesGenerator = new KDF2BytesGenerator(sha256);
        byte[] shared = RandomUtils.nextBytes(90);
        System.out.println(EncodeUtils.base64Encode(shared));
        byte[] iv = RandomUtils.nextBytes(sha256.getDigestSize());
        System.out.println(EncodeUtils.base64Encode(iv));
        KDFParameters kdfParameters = new KDFParameters(shared, iv);
        kdf2BytesGenerator.init(kdfParameters);
        byte[] out = new byte[sha256.getDigestSize()];
        kdf2BytesGenerator.generateBytes(out, 0, sha256.getDigestSize());
        System.out.println(EncodeUtils.base64Encode(out));
    }

}
