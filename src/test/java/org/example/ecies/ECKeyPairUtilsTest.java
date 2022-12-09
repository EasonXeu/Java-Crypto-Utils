package org.example.ecies;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import static org.example.EncodeUtils.base64Decode;
import static org.example.EncodeUtils.base64Encode;
import static org.example.ecies.ECKeyPairUtils.deserializePrivateKeyInBigIntFormat;
import static org.example.ecies.ECKeyPairUtils.deserializePublicKeyInBigIntFormat;
import static org.example.ecies.ECKeyPairUtils.serializePrivateKeyInBigIntFormat;
import static org.example.ecies.ECKeyPairUtils.serializePublicKeyInBigIntFormat;
import org.junit.Test;

public class ECKeyPairUtilsTest {

    @Test
    public void testInBigIntFormat() throws Exception {
        String publicKeyInBigIntFormat =
            "BPQZbsm7m4lIYR-qcUaMP3bqpVTa4f4fYm-z3nUnmTRVtENKgXb-qKXbvbnlZJF-MisHIpeXvr5-BiC5wu8MyDk";
        String privateKeyInBigIntFormat = "CHpSGAU0mdxEs-C9ZMbEiSGImirK4f7ngkQS3fslGsQ";
        BCECPublicKey bcecPublicKey = deserializePublicKeyInBigIntFormat(base64Decode(publicKeyInBigIntFormat));
        BCECPrivateKey bcecPrivateKey = deserializePrivateKeyInBigIntFormat(base64Decode(privateKeyInBigIntFormat));

        String privateKeyString = base64Encode(serializePrivateKeyInBigIntFormat(bcecPrivateKey));
        String publicKeyString = base64Encode(serializePublicKeyInBigIntFormat(bcecPublicKey));

        System.out.println(privateKeyInBigIntFormat.equals(privateKeyString));
        System.out.println(publicKeyInBigIntFormat.equals(publicKeyString));
    }
}