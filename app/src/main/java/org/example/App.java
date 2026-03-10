package org.example;

import java.util.Arrays;
import java.util.HashMap;
import java.nio.ByteBuffer;

public class App {
    public HashMap<String, byte[]> data = new HashMap<>();
    public byte[] k1 = new byte[8];
    public byte[] k2 = new byte[8];

    App() {
        RAWDATA();
    }

    public static void main(String[] args) {
        App app = new App();
        app.KeyGeneration(app.data.get("rawKey2"));
    }

    public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
        return new byte[0];
    }

    public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
        return new byte[0];
    }

    public void KeyGeneration(byte[] rawkey) {
        byte[] p10 = data.get("P10").clone();
        byte[] rawkeyClone = rawkey.clone();
        byte[] k1 = permuteArray(rawkeyClone, p10);
        leftShiftBothHalves(k1, 1);
        byte[] ls1 = k1.clone();
        byte[] p8 = data.get("P8").clone();
        k1 = permuteArray(k1, p8);
        leftShiftBothHalves(ls1, 2);
        byte[] k2 = permuteArray(ls1, p8);
        this.k1 = k1;
        this.k2 = k2;
    }

    // P10(k1,k2,k3,k4,k5,k6,k7,k8,k9,k10) = (k3,k5,k2,k7,k4,k10,k1,k9,k8,k6)
    static byte[] permuteArray(byte[] src, byte[] by) {
        byte[] dst = new byte[by.length];
        for (int i = 0; i < by.length; i++) {
            dst[i] = src[by[i] - 1];
        }
        return dst;
    }

    static byte[] leftShift(byte[] input, int shift) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            int shiftIndex = Math.floorMod((i - shift), input.length);
            output[shiftIndex] = input[i];
        }
        return output;
    }

    static void leftShiftBothHalves(byte[] arr, int shift) {
        byte[] leftHalf = new byte[arr.length / 2];
        byte[] rightHalf = new byte[arr.length / 2];
        for (int i = 0; i < arr.length / 2; i++) {
            leftHalf[i] = arr[i];
            rightHalf[i] = arr[i + arr.length / 2];
        }
        byte[] l = leftShift(leftHalf, shift);
        byte[] r = leftShift(rightHalf, shift);
        for (int i = 0; i < arr.length / 2; i++) {
            arr[i] = l[i];
            arr[i + arr.length / 2] = r[i];
        }
    }

    void RAWDATA() {
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
        byte[] IP = { 2, 6, 3, 1, 4, 8, 5, 7 };
        byte[] IPinverse = { 4, 1, 3, 5, 7, 2, 8, 6 };
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
        data.put("IP", IP);
        data.put("IPinverse", IPinverse);
    }
}
