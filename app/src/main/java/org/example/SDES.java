package org.example;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.example.TripleDES;

public class SDES {
    public HashMap<String, byte[]> data = new HashMap<>();
    public byte[] k1 = new byte[8];
    public byte[] k2 = new byte[8];

    SDES() {
        RAWDATA();
    }

    public static void main(String[] args) {
        SDES app = new SDES();

        app.printTable(false);
        app.printTable(true);

        System.out.println("Cracking the code");
        crackTheCode("../assets/msg1.txt");
    }

    static void crackTheCode(String path) {
        try {
            String ciphertextBits = Files.readString(Path.of(path), StandardCharsets.UTF_8).replaceAll("\\s+", "");
            Path outputDir = Path.of("../assets", "msg1");
            Files.createDirectories(outputDir);

            for (int i = 0; i < (1 << 10); ++i) {
                String byteString = String.format("%10s", Integer.toBinaryString(i)).replace(' ', '0');
                byte[] rawkey = parseBinaryByte(byteString);

                try (FileOutputStream fos = new FileOutputStream(
                        outputDir.resolve(byteString + "_" + i + ".txt").toFile())) {
                    for (int j = 0; j < ciphertextBits.length(); j += 8) {
                        byte[] ciphertext = parseBinaryByte(ciphertextBits.substring(j, j + 8));
                        byte[] plaintext = Decrypt(rawkey, ciphertext);
                        byte b = bitsToByte(plaintext);
                        fos.write(b);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String bitsToAscii(byte[] bitArray) {
        if (bitArray.length % 8 != 0) {
            throw new IllegalArgumentException("Array length must be a multiple of 8.");
        }

        byte[] resultBytes = new byte[bitArray.length / 8];
        for (int i = 0; i < resultBytes.length; i++) {
            int byteValue = 0;
            for (int bit = 0; bit < 8; bit++) {
                // Shift existing bits left and add the new bit
                byteValue = (byteValue << 1) | (bitArray[i * 8 + bit] & 1);
            }
            resultBytes[i] = (byte) byteValue;
        }

        return new String(resultBytes, StandardCharsets.US_ASCII);
    }

    static byte[] parseBinaryByte(String bits) {
        byte[] output = new byte[bits.length()];
        for (int i = 0; i < bits.length(); ++i) {
            char bit = bits.charAt(i);
            if (bit != '0' && bit != '1') {
                // last char is empty
                // just break
                break;
            }
            output[i] = (byte) (bit - '0');
        }
        return output;
    }

    static int bitsToByteValue(byte[] bits) {
        if (bits.length != 8) {
            throw new IllegalArgumentException("Expected exactly 8 bits");
        }

        int value = 0;
        for (byte bit : bits) {
            if (bit != 0 && bit != 1) {
                throw new IllegalArgumentException("Bit arrays must contain only 0 or 1");
            }
            value = (value << 1) | bit;
        }
        return value;
    }

    public static byte bitsToByte(byte[] bits) {
        int value = 0;
        for (int i = 0; i < 8; i++) {
            // Shift left and OR the bit to build the 8-bit value
            value = (value << 1) | (bits[i] & 1);
        }
        return (byte) value;
    }

    List<byte[]> part3(String text_to_encode) {
        String text = text_to_encode;
        byte[] byteArray = text.getBytes();
        List<byte[]> bytes = new ArrayList<>();
        for (byte b : byteArray) {
            String byteString = String.format("%8s", Integer.toBinaryString(b)).replace(' ', '0');
            bytes.add(parseBinaryByte(byteString));
        }
        return bytes;
    }

    void printTable(boolean x3) {
        String format;
        if (!x3) {
            format = "%-31s %-25s %25s%n";
            System.out.printf(format, "Raw Key", "Plaintext", "Ciphertext");
            for (int i = 0; i < 4; ++i) {
                byte[] rawkey = data.get("rawkeyTable" + i);
                byte[] plaintext = data.get("plaintextTable" + i);
                byte[] ciphertext = Encrypt(rawkey, plaintext);
                System.out.printf(format, Arrays.toString(rawkey), Arrays.toString(plaintext),
                        Arrays.toString(ciphertext));
            }
            for (int i = 4; i < 8; ++i) {
                byte[] rawkey = data.get("rawkeyTable" + i);
                byte[] ciphertext = data.get("ciphertextTable" + i);
                byte[] plaintext = Decrypt(rawkey, ciphertext);
                System.out.printf(format, Arrays.toString(rawkey), Arrays.toString(plaintext),
                        Arrays.toString(ciphertext));
            }
            return;
        }

        format = "%-31s %-31s %-25s %25s%n";
        System.out.printf(format, "Raw Key 1", "Raw Key", "Plaintext", "Ciphertext");
        for (int i = 0; i < 4; ++i) {
            byte[] rawkey1 = data.get("tripleRawkey1Table" + i);
            byte[] rawkey2 = data.get("tripleRawkey2Table" + i);
            byte[] plaintext = data.get("triplePlaintextTable" + i);
            byte[] ciphertext = TripleDES.E3SDES(rawkey1, rawkey2, plaintext);
            System.out.printf(
                    format,
                    Arrays.toString(rawkey1),
                    Arrays.toString(rawkey2),
                    Arrays.toString(plaintext),
                    Arrays.toString(ciphertext));
        }
        for (int i = 4; i < 8; ++i) {
            byte[] rawkey1 = data.get("tripleRawkey1Table" + i);
            byte[] rawkey2 = data.get("tripleRawkey2Table" + i);
            byte[] ciphertext = data.get("tripleCiphertextTable" + i);
            byte[] plaintext = TripleDES.D3SDES(rawkey1, rawkey2, ciphertext);
            System.out.printf(
                    format,
                    Arrays.toString(rawkey1),
                    Arrays.toString(rawkey2),
                    Arrays.toString(plaintext),
                    Arrays.toString(ciphertext));
        }
    }

    void encryptTest(int num) {
        byte[] rawkey = data.get("rawkey" + num);
        byte[] plaintext = data.get("plaintext" + num);
        String ciphertext = Arrays.toString(Encrypt(rawkey, plaintext));
        System.out.printf("Encrypt(%s, %s) == %s\n", Arrays.toString(rawkey), Arrays.toString(plaintext), ciphertext);
    }

    public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
        SDES app = new SDES();
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
        SDES app = new SDES();
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
        byte[] rawkeyTable0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] rawkeyTable1 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] rawkeyTable2 = { 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 };
        byte[] rawkeyTable3 = { 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 };
        byte[] rawkeyTable4 = { 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
        byte[] rawkeyTable5 = { 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
        byte[] rawkeyTable6 = { 0, 0, 1, 0, 0, 1, 1, 1, 1, 1 };
        byte[] rawkeyTable7 = { 0, 0, 1, 0, 0, 1, 1, 1, 1, 1 };
        byte[] plaintextTable0 = { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] plaintextTable1 = { 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] plaintextTable2 = { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] plaintextTable3 = { 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] ciphertextTable4 = { 0, 0, 0, 1, 1, 1, 0, 0 };
        byte[] ciphertextTable5 = { 1, 1, 0, 0, 0, 0, 1, 0 };
        byte[] ciphertextTable6 = { 1, 0, 0, 1, 1, 1, 0, 1 };
        byte[] ciphertextTable7 = { 1, 0, 0, 1, 0, 0, 0, 0 };
        byte[] rawkey0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] rawkey1 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
        byte[] rawkey2 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
        byte[] rawkey3 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] plaintext0 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] plaintext1 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] plaintext2 = { 0, 1, 0, 1, 0, 1, 0, 1 };
        byte[] plaintext3 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] ciphertext0 = { 0, 0, 0, 1, 0, 0, 0, 1 };
        byte[] ciphertext1 = { 1, 1, 0, 0, 1, 0, 1, 0 };
        byte[] ciphertext2 = { 0, 1, 1, 1, 0, 0, 0, 0 };
        byte[] ciphertext3 = { 0, 0, 0, 0, 0, 1, 0, 0 };
        byte[] tripleRawkey1Table0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] tripleRawkey2Table0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] tripleRawkey1Table1 = { 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
        byte[] tripleRawkey2Table1 = { 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
        byte[] tripleRawkey1Table2 = { 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
        byte[] tripleRawkey2Table2 = { 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
        byte[] tripleRawkey1Table3 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] tripleRawkey2Table3 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] tripleRawkey1Table4 = { 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
        byte[] tripleRawkey2Table4 = { 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
        byte[] tripleRawkey1Table5 = { 1, 0, 1, 1, 1, 0, 1, 1, 1, 1 };
        byte[] tripleRawkey2Table5 = { 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
        byte[] tripleRawkey1Table6 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] tripleRawkey2Table6 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] tripleRawkey1Table7 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] tripleRawkey2Table7 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] triplePlaintextTable0 = { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] triplePlaintextTable1 = { 1, 1, 0, 1, 0, 1, 1, 1 };
        byte[] triplePlaintextTable2 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] triplePlaintextTable3 = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] tripleCiphertextTable4 = { 1, 1, 1, 0, 0, 1, 1, 0 };
        byte[] tripleCiphertextTable5 = { 0, 1, 0, 1, 0, 0, 0, 0 };
        byte[] tripleCiphertextTable6 = { 1, 0, 0, 0, 0, 0, 0, 0 };
        byte[] tripleCiphertextTable7 = { 1, 0, 0, 1, 0, 0, 1, 0 };
        byte[] P10 = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };
        byte[] P8 = { 6, 3, 7, 4, 8, 5, 10, 9 };
        byte[] P4 = { 2, 4, 3, 1 };
        byte[] IP = { 2, 6, 3, 1, 4, 8, 5, 7 };
        byte[] IPinverse = { 4, 1, 3, 5, 7, 2, 8, 6 };
        byte[] EP = { 4, 1, 2, 3, 2, 3, 4, 1 };
        data.put("rawkey0", rawkey0);
        data.put("rawkey1", rawkey1);
        data.put("rawkey2", rawkey2);
        data.put("rawkey3", rawkey3);
        data.put("plaintext0", plaintext0);
        data.put("plaintext1", plaintext1);
        data.put("plaintext2", plaintext2);
        data.put("plaintext3", plaintext3);
        data.put("ciphertext0", ciphertext0);
        data.put("ciphertext1", ciphertext1);
        data.put("ciphertext2", ciphertext2);
        data.put("ciphertext3", ciphertext3);

        data.put("rawkeyTable0", rawkeyTable0);
        data.put("rawkeyTable1", rawkeyTable1);
        data.put("rawkeyTable2", rawkeyTable2);
        data.put("rawkeyTable3", rawkeyTable3);
        data.put("rawkeyTable4", rawkeyTable4);
        data.put("rawkeyTable5", rawkeyTable5);
        data.put("rawkeyTable6", rawkeyTable6);
        data.put("rawkeyTable7", rawkeyTable7);

        data.put("plaintextTable0", plaintextTable0);
        data.put("plaintextTable1", plaintextTable1);
        data.put("plaintextTable2", plaintextTable2);
        data.put("plaintextTable3", plaintextTable3);
        data.put("ciphertextTable4", ciphertextTable4);
        data.put("ciphertextTable5", ciphertextTable5);
        data.put("ciphertextTable6", ciphertextTable6);
        data.put("ciphertextTable7", ciphertextTable7);

        data.put("tripleRawkey1Table0", tripleRawkey1Table0);
        data.put("tripleRawkey2Table0", tripleRawkey2Table0);
        data.put("tripleRawkey1Table1", tripleRawkey1Table1);
        data.put("tripleRawkey2Table1", tripleRawkey2Table1);
        data.put("tripleRawkey1Table2", tripleRawkey1Table2);
        data.put("tripleRawkey2Table2", tripleRawkey2Table2);
        data.put("tripleRawkey1Table3", tripleRawkey1Table3);
        data.put("tripleRawkey2Table3", tripleRawkey2Table3);
        data.put("tripleRawkey1Table4", tripleRawkey1Table4);
        data.put("tripleRawkey2Table4", tripleRawkey2Table4);
        data.put("tripleRawkey1Table5", tripleRawkey1Table5);
        data.put("tripleRawkey2Table5", tripleRawkey2Table5);
        data.put("tripleRawkey1Table6", tripleRawkey1Table6);
        data.put("tripleRawkey2Table6", tripleRawkey2Table6);
        data.put("tripleRawkey1Table7", tripleRawkey1Table7);
        data.put("tripleRawkey2Table7", tripleRawkey2Table7);

        data.put("triplePlaintextTable0", triplePlaintextTable0);
        data.put("triplePlaintextTable1", triplePlaintextTable1);
        data.put("triplePlaintextTable2", triplePlaintextTable2);
        data.put("triplePlaintextTable3", triplePlaintextTable3);
        data.put("tripleCiphertextTable4", tripleCiphertextTable4);
        data.put("tripleCiphertextTable5", tripleCiphertextTable5);
        data.put("tripleCiphertextTable6", tripleCiphertextTable6);
        data.put("tripleCiphertextTable7", tripleCiphertextTable7);

        data.put("P10", P10);
        data.put("P8", P8);
        data.put("P4", P4);
        data.put("IP", IP);
        data.put("IPinverse", IPinverse);
        data.put("EP", EP);
    }
}
