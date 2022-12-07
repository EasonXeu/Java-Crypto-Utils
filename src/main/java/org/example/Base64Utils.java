package org.example;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class Base64Utils {

    public static String encodeBase64String(byte[] data) {
        return Base64.encodeBase64String(data);
    }

    public static byte[] decodeBase64String(String data) {
        return Base64.decodeBase64(data);
    }

    public static String encodeHexString(byte[] data) {
        return Hex.encodeHexString(data);
    }

    public static byte[] decodeHexString(String data)  {
        try {
            return Hex.decodeHex(data);
        }catch (Exception e){
            return null;
        }
    }

}
