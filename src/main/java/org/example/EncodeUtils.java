package org.example;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class EncodeUtils {

    public static String base64Encode(byte[] data) {
        return Base64.encodeBase64String(data);
    }

    public static byte[] base64Decode(String data) {
        return Base64.decodeBase64(data);
    }

    public static String hexEncode(byte[] data) {
        return Hex.encodeHexString(data);
    }

    public static byte[] hexDecode(String data) {
        try {
            return Hex.decodeHex(data);
        } catch (Exception e) {
            return null;
        }
    }

}
