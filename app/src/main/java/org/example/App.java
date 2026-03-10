package org.example;

import java.util.HashMap;

public class App {
    HashMap<String, byte[]> data = new HashMap<>();

    App() {
        RAWDATA();
    }

    public static void main(String[] args) {
    }

    public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
        return new byte[0];
    }

    public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
        return new byte[0];
    }

    void RAWDATA() {
        // Raw Key Plaintext Ciphertext
        byte[] rawKey0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] rawKey1 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
        byte[] rawKey2 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
        byte[] rawKey3 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] plainText0 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] plainText1 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] plainText2 = { 0, 1, 0, 1, 0, 1, 0, 1 };
        byte[] plainText3 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] cipherText0 = { 0, 0, 0, 1, 0, 0, 0, 1 };
        byte[] cipherText1 = { 1, 1, 0, 0, 1, 0, 1, 0 };
        byte[] cipherText2 = { 0, 1, 1, 1, 0, 0, 0, 0 };
        byte[] cipherText3 = { 0, 0, 0, 0, 0, 1, 0, 0 };
        byte[] P10 = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };
        byte[] P8 = { 6, 3, 7, 4, 8, 5, 10, 9 };
        data.put("rawKey0", rawKey0);
        data.put("rawKey1", rawKey1);
        data.put("rawKey2", rawKey2);
        data.put("rawKey3", rawKey3);
        data.put("plainText0", plainText0);
        data.put("plainText1", plainText1);
        data.put("plainText2", plainText2);
        data.put("plainText3", plainText3);
        data.put("cipherText0", cipherText0);
        data.put("cipherText1", cipherText1);
        data.put("cipherText2", cipherText2);
        data.put("cipherText3", cipherText3);
        data.put("P10", P10);
        data.put("P8", P8);
    }
}
