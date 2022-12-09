package org.example.ecies.common;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.util.BigIntegers;
import org.example.ecies.ECKeyPairUtils;
import org.junit.Assert;
import org.junit.Test;

public class CommonECIESUtilsTest {
    @Test
    public void test() throws Exception {
        String msg = "Hello=world";
        BigInteger x =
            new BigInteger("52413894827588956828540116071419489832257099287803359527612918773114920555825", 10);
        BigInteger y =
            new BigInteger("20272985080232993907728107144350834831754799721380728724611957051120539586069", 10);
        BigInteger d =
            new BigInteger("8155345353664413521026415600331432382231081770303345925413249020265351134605", 10);

        // deserialize key and use them
        PublicKey publicKey = ECKeyPairUtils.deserializePublicKeyInBigIntFormat(
            BigIntegers.asUnsignedByteArray(x),
            BigIntegers.asUnsignedByteArray(y)
        );
        PrivateKey privateKey = ECKeyPairUtils.deserializePrivateKeyInBigIntFormat(
            BigIntegers.asUnsignedByteArray(d)
        );

        String cipherText =
            "BOcQYOW1tP1lVgG4raVWU2YubhZQlSs7cey3kmo1v92vNibl1yCRiZ-aMjHpdZEsy3bOn_bW8J-RCKrac3x-2YZ6Ahv-2lwOGhTrTpHNoQ6XRHvBz5oPH9KWbcVOgnhwjoiePLEyAprZCCx4aeiUFaE";

        String plainMsg =
            new String(CommonECIESUtils.decrypt(cipherText, (BCECPrivateKey) privateKey), StandardCharsets.UTF_8);
        Assert.assertEquals(plainMsg, msg);
    }
}