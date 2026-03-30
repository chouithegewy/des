package org.example;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class App {
    public HashMap<String, byte[]> data = new HashMap<>();
    public byte[] k1 = new byte[8];
    public byte[] k2 = new byte[8];

    App() {
        RAWDATA();
    }

    public static void main(String[] args) {
        App app = new App();
        // System.out.println("Some test cases...");
        // app.encryptTest(0);
        // app.encryptTest(1);
        // app.encryptTest(2);
        // app.encryptTest(3);
        app.printTable();
    }

    void printTable() {
        String format = "%-31s %-25s %25s%n";
        System.out.printf(format, "rawkey", "plaintext", "ciphertext");
        for (int i = 0; i < 4; ++i) {
            byte[] rawkey = data.get("rawKeyTable" + i);
            byte[] plaintext = data.get("plaintextTable" + i);
            byte[] ciphertext = Encrypt(rawkey, plaintext);
            System.out.printf(format, Arrays.toString(rawkey), Arrays.toString(plaintext), Arrays.toString(ciphertext));
        }
        for (int i = 4; i < 8; ++i) {
            byte[] rawkey = data.get("rawKeyTable" + i);
            byte[] ciphertext = data.get("ciphertextTable" + i);
            byte[] plaintext = Decrypt(rawkey, ciphertext);
            System.out.printf(format, Arrays.toString(rawkey), Arrays.toString(plaintext), Arrays.toString(ciphertext));
        }
    }

    void encryptTest(int num) {
        byte[] rawKey = data.get("rawKey" + num);
        byte[] plaintext = data.get("plaintext" + num);
        String ciphertext = Arrays.toString(Encrypt(rawKey, plaintext));
        System.out.printf("Encrypt(%s, %s) == %s\n", Arrays.toString(rawKey), Arrays.toString(plaintext), ciphertext);
    }

    public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
        App app = new App();
        app.KeyGeneration(rawkey);

        byte[] ip = initialPermutation(plaintext);

        byte[] p4_1 = app.fk(ip, app.k1);
        byte[] l4ip_1 = new byte[ip.length / 2];
        System.arraycopy(ip, 0, l4ip_1, 0, ip.length / 2);
        byte[] p4_1_xor = xor(p4_1, l4ip_1);
        byte[] resultOfSwitch = sw(p4_1_xor, ip);

        byte[] p4_2 = app.fk(resultOfSwitch, app.k2);
        byte[] leftFourBitsOfSwitch = new byte[ip.length / 2];
        System.arraycopy(resultOfSwitch, 0, leftFourBitsOfSwitch, 0, ip.length / 2);
        byte[] p4_2_xor = xor(p4_2, leftFourBitsOfSwitch);

        byte[] p4_2_xor_rightFourBitsSwitch = new byte[8];
        System.arraycopy(p4_2_xor, 0, p4_2_xor_rightFourBitsSwitch, 0, ip.length / 2);
        System.arraycopy(resultOfSwitch, 4, p4_2_xor_rightFourBitsSwitch, 4, ip.length / 2);

        return inverseInitialPermutation(p4_2_xor_rightFourBitsSwitch);
    }

    public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
        App app = new App();
        app.KeyGeneration(rawkey);

        byte[] ip = initialPermutation(ciphertext);
        byte[] p4_2 = app.fk(ip, app.k2);
        byte[] l4ip_2 = new byte[ip.length / 2];
        System.arraycopy(ip, 0, l4ip_2, 0, ip.length / 2);
        byte[] p4_2_xor = xor(p4_2, l4ip_2);
        byte[] resultOfSwitch = sw(p4_2_xor, ip);

        byte[] p4_1 = app.fk(resultOfSwitch, app.k1);
        byte[] leftFourBitsOfSwitch = new byte[ip.length / 2];
        System.arraycopy(resultOfSwitch, 0, leftFourBitsOfSwitch, 0, ip.length / 2);
        byte[] p4_1_xor = xor(p4_1, leftFourBitsOfSwitch);

        byte[] p4_1_xor_rightFourBitsSwitch = new byte[8];
        System.arraycopy(p4_1_xor, 0, p4_1_xor_rightFourBitsSwitch, 0, ip.length / 2);
        System.arraycopy(resultOfSwitch, 4, p4_1_xor_rightFourBitsSwitch, 4, ip.length / 2);

        return inverseInitialPermutation(p4_1_xor_rightFourBitsSwitch);
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

    static byte[] expansionPermutation(byte[] input, byte[] ep) {
        byte[] exp = new byte[ep.length];
        for (int i = 0; i < ep.length; i++) {
            exp[i] = input[ep[i] - 1];
        }
        return exp;
    }

    static byte[] xor(byte[] a, byte[] b) {
        byte[] exclusiveOr = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            exclusiveOr[i] = (byte) (a[i] ^ b[i]);
        }
        return exclusiveOr;
    }

    static byte[] s0(byte[] l) {
        byte[][] sBox0 = { { 1, 0, 3, 2 }, { 3, 2, 1, 0, }, { 0, 2, 1, 3 }, { 3, 1, 3, 2 } };
        int row = (l[0] << 1) | l[3];
        int col = (l[1] << 1) | l[2];
        byte twoBitNum = sBox0[row][col];
        byte[] output = new byte[2];
        output[0] = (byte) ((twoBitNum >> 1) & 1);
        output[1] = (byte) (twoBitNum & 1);

        return output;
    }

    static byte[] s1(byte[] r) {
        byte[][] sBox1 = { { 0, 1, 2, 3 }, { 2, 0, 1, 3 }, { 3, 0, 1, 0 }, { 2, 1, 0, 3 } };
        int row = (r[0] << 1) | r[3];
        int col = (r[1] << 1) | r[2];

        byte twoBitNum = sBox1[row][col];
        byte[] output = new byte[2];
        output[0] = (byte) ((twoBitNum >> 1) & 1);
        output[1] = (byte) (twoBitNum & 1);

        return output;
    }

    static byte[] initialPermutation(byte[] plaintext) {
        byte[] IP = { 2, 6, 3, 1, 4, 8, 5, 7 };
        return permuteArray(plaintext, IP);
    }

    static byte[] inverseInitialPermutation(byte[] a) {
        byte[] IPinverse = { 4, 1, 3, 5, 7, 2, 8, 6 };
        return permuteArray(a, IPinverse);
    }

    byte[] fk(byte[] ip, byte[] key) {
        byte[] r = new byte[4];
        for (int i = 4; i < 8; i++) {
            r[i - 4] = ip[i];
        }
        byte[] ep = { 4, 1, 2, 3, 2, 3, 4, 1 };
        byte[] exp = expansionPermutation(r, ep);
        byte[] xord = xor(exp, key);
        byte[] leftHalf = new byte[4];
        byte[] rightHalf = new byte[4];
        System.arraycopy(xord, 0, leftHalf, 0, 4);
        System.arraycopy(xord, 4, rightHalf, 0, 4);
        byte[] es0 = s0(leftHalf);
        byte[] es1 = s1(rightHalf);
        byte[] p4 = new byte[4];
        p4[0] = es0[0];
        p4[1] = es0[1];
        p4[2] = es1[0];
        p4[3] = es1[1];
        byte[] P4 = { 2, 4, 3, 1 };
        return permuteArray(p4, P4);
    }

    // swap a with right 4 of b
    static byte[] sw(byte[] l, byte[] r) {
        byte[] output = new byte[8];
        System.arraycopy(r, 4, output, 0, 4);
        System.arraycopy(l, 0, output, 4, 4);
        return output;
    }

    void RAWDATA() {
        byte[] rawKeyTable0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] rawKeyTable1 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] rawKeyTable2 = { 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 };
        byte[] rawKeyTable3 = { 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 };
        byte[] rawKeyTable4 = { 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
        byte[] rawKeyTable5 = { 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
        byte[] rawKeyTable6 = { 0, 0, 1, 0, 0, 1, 1, 1, 1, 1 };
        byte[] rawKeyTable7 = { 0, 0, 1, 0, 0, 1, 1, 1, 1, 1 };
        byte[] plaintextTable0 = { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] plaintextTable1 = { 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] plaintextTable2 = { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] plaintextTable3 = { 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] ciphertextTable4 = { 0, 0, 0, 1, 1, 1, 0, 0 };
        byte[] ciphertextTable5 = { 1, 1, 0, 0, 0, 0, 1, 0 };
        byte[] ciphertextTable6 = { 1, 0, 0, 1, 1, 1, 0, 1 };
        byte[] ciphertextTable7 = { 1, 0, 0, 1, 0, 0, 0, 0 };
        byte[] rawKey0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] rawKey1 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
        byte[] rawKey2 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
        byte[] rawKey3 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] plaintext0 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] plaintext1 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] plaintext2 = { 0, 1, 0, 1, 0, 1, 0, 1 };
        byte[] plaintext3 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] ciphertext0 = { 0, 0, 0, 1, 0, 0, 0, 1 };
        byte[] ciphertext1 = { 1, 1, 0, 0, 1, 0, 1, 0 };
        byte[] ciphertext2 = { 0, 1, 1, 1, 0, 0, 0, 0 };
        byte[] ciphertext3 = { 0, 0, 0, 0, 0, 1, 0, 0 };
        byte[] P10 = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };
        byte[] P8 = { 6, 3, 7, 4, 8, 5, 10, 9 };
        byte[] P4 = { 2, 4, 3, 1 };
        byte[] IP = { 2, 6, 3, 1, 4, 8, 5, 7 };
        byte[] IPinverse = { 4, 1, 3, 5, 7, 2, 8, 6 };
        byte[] EP = { 4, 1, 2, 3, 2, 3, 4, 1 };
        data.put("rawKey0", rawKey0);
        data.put("rawKey1", rawKey1);
        data.put("rawKey2", rawKey2);
        data.put("rawKey3", rawKey3);
        data.put("plaintext0", plaintext0);
        data.put("plaintext1", plaintext1);
        data.put("plaintext2", plaintext2);
        data.put("plaintext3", plaintext3);
        data.put("ciphertext0", ciphertext0);
        data.put("ciphertext1", ciphertext1);
        data.put("ciphertext2", ciphertext2);
        data.put("ciphertext3", ciphertext3);

        data.put("rawKeyTable0", rawKeyTable0);
        data.put("rawKeyTable1", rawKeyTable1);
        data.put("rawKeyTable2", rawKeyTable2);
        data.put("rawKeyTable3", rawKeyTable3);
        data.put("rawKeyTable4", rawKeyTable4);
        data.put("rawKeyTable5", rawKeyTable5);
        data.put("rawKeyTable6", rawKeyTable6);
        data.put("rawKeyTable7", rawKeyTable7);

        data.put("plaintextTable0", plaintextTable0);
        data.put("plaintextTable1", plaintextTable1);
        data.put("plaintextTable2", plaintextTable2);
        data.put("plaintextTable3", plaintextTable3);
        data.put("ciphertextTable4", ciphertextTable4);
        data.put("ciphertextTable5", ciphertextTable5);
        data.put("ciphertextTable6", ciphertextTable6);
        data.put("ciphertextTable7", ciphertextTable7);

        data.put("P10", P10);
        data.put("P8", P8);
        data.put("P4", P4);
        data.put("IP", IP);
        data.put("IPinverse", IPinverse);
        data.put("EP", EP);
    }
}
