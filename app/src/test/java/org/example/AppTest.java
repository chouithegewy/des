package org.example;

import java.util.Arrays;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import static org.example.App.Encrypt;
import static org.example.App.Decrypt;
import static org.example.App.leftShift;
import static org.example.App.permuteArray;
import static org.example.App.expansionPermutation;
import static org.example.App.xor;
import static org.example.App.s0;
import static org.example.App.s1;
import static org.example.App.sw;

class AppTest {
    static HashMap<String, byte[]> data = new HashMap<>();
    static App app;

    @BeforeAll
    static void generateData() {
        App testApp = new App();
        data = testApp.data;
        app = testApp;
    }

    @Test
    void leftShiftTest() {
        assertEquals(Arrays.toString(leftShift(app.data.get("rawKey0").clone(), 1)),
                Arrays.toString(app.data.get("rawKey0").clone()));
        assertEquals(Arrays.toString(leftShift(app.data.get("rawKey0").clone(), 2)),
                Arrays.toString(app.data.get("rawKey0").clone()));
        byte[] zeros = app.data.get("rawKey0").clone();
        zeros[0] = 1;
        byte[] one = app.data.get("rawKey0").clone();
        one[one.length - 1] = 1;
        assertEquals(Arrays.toString(one), Arrays.toString(leftShift(zeros, 1)));
        one[one.length - 1] = 0;
        one[one.length - 2] = 1;
        assertEquals(Arrays.toString(one), Arrays.toString(leftShift(zeros, 2)));
    }

    @Test
    void keyGenerationTest() {
        byte[] exampleFromDocument = { 1, 0, 1, 0, 0, 0, 0, 0, 1, 0 };
        app.KeyGeneration(exampleFromDocument);
        byte[] expectedK1 = { 1, 0, 1, 0, 0, 1, 0, 0 };
        byte[] expectedK2 = { 0, 1, 0, 0, 0, 0, 1, 1 };
        assertEquals(Arrays.toString(expectedK1), Arrays.toString(app.k1));
        assertEquals(Arrays.toString(expectedK2), Arrays.toString(app.k2));
    }

    @Test
    void leftShiftBothHalvesTest() {
        byte[] zeros = app.data.get("rawKey0").clone();
        zeros[0] = 1;
        zeros[5] = 1;
        // 1000010000
        byte[] one = app.data.get("rawKey0").clone();
        one[one.length - 1] = 1;
        one[one.length - 6] = 1;
        // 0000100001
        assertEquals(Arrays.toString(one), Arrays.toString(leftShift(zeros, 1)));
        one[one.length - 1] = 0;
        one[one.length - 2] = 1;
        one[one.length - 6] = 0;
        one[one.length - 7] = 1;
        // 0001000010
        assertEquals(Arrays.toString(one), Arrays.toString(leftShift(zeros, 2)));
    }

    @Test
    void permuteArrayTestP8() {
        byte[] p8 = app.data.get("P8").clone();
        byte[] rawKey1 = app.data.get("rawKey1").clone();
        byte[] permuted = permuteArray(rawKey1, p8);
        assertEquals(p8.length, permuted.length);
        // rawKey1 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 }
        // p8 = { 6, 3, 7, 4, 8, 5, 10, 9 }
        byte[] expected = { 0, 1, 1, 0, 1, 0, 0, 1 };
        assertEquals(Arrays.toString(expected), Arrays.toString(permuted));
    }

    @Test
    void permuteArrayTestP10() {
        byte[] p10 = app.data.get("P10").clone();
        byte[] rawKey1 = app.data.get("rawKey1").clone();
        byte[] permuted = permuteArray(rawKey1, p10);
        assertEquals(p10.length, permuted.length);
        // rawKey1 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 }
        // p10 = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 }
        byte[] expected = { 1, 0, 1, 1, 0, 0, 1, 1, 1, 0 };
        assertEquals(Arrays.toString(expected), Arrays.toString(permuted));
    }

    @Test
    void ipInverseIPTest() {
        byte[] ip = app.data.get("IP").clone();
        byte[] inverseIP = app.data.get("IPinverse").clone();
        byte[] plainText0 = app.data.get("plainText0").clone();
        byte[] permuted = permuteArray(plainText0, ip);
        byte[] inversePermuted = permuteArray(permuted, inverseIP);
        assertEquals(Arrays.toString(plainText0), Arrays.toString(inversePermuted));
    }

    @Test
    void expansionPermutationTest() {
        byte[] ep = app.data.get("EP").clone();
        byte[] fourBitKey = { 1, 0, 0, 1 };
        byte[] result = expansionPermutation(fourBitKey, ep);
        byte[] expected = { 1, 1, 0, 0, 0, 0, 1, 1 };
        // rawKey1 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 }
        // EP = { 4, 1, 2, 3, 2, 3, 4, 1 }
        // expected= { 1, 1, 0, 0, 0, 0, 1, 1 }
        assertEquals(Arrays.toString(expected), Arrays.toString(result));
    }

    @Test
    void xorTest() {
        byte[] test = { 1, 0, 1, 0, 1, 0, 1, 0 };
        byte[] ones = { 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] expected = { 0, 1, 0, 1, 0, 1, 0, 1 };
        assertEquals(Arrays.toString(expected), Arrays.toString(xor(test, ones)));
    }

    @Test
    void sBox0() {
        byte[] fourBitKey = { 0, 1, 1, 0 };
        // sBox0 = { { 1, 0, 3, 2 }, { 3, 2, 1, 0, }, { 0, 2, 1, 3 }, { 3, 1, 3, 2 } };
        byte[] result = s0(fourBitKey);
        byte[] expected11 = { 1, 0 };
        assertEquals(Arrays.toString(expected11), Arrays.toString(result));
    }

    @Test
    void sBox1() {
        byte[] anotherFourBitKey = { 0, 1, 1, 1 };
        byte[] result = s1(anotherFourBitKey); // [1][3]
        // sBox1 = { { 0, 1, 2, 3 }, { 2, 0, 1, 3, }, { 3, 0, 1, 0 }, { 2, 1, 0, 3 } };
        byte[] expected11 = { 1, 1 };
        assertEquals(Arrays.toString(expected11), Arrays.toString(result));
    }

    @Test
    void keyGen2IP2EP2skXORes0es1p4FK() {
        byte[] exampleFromDocument = { 1, 0, 1, 0, 0, 0, 0, 0, 1, 0 };
        app.KeyGeneration(exampleFromDocument);
        byte[] expectedK1 = { 1, 0, 1, 0, 0, 1, 0, 0 };
        byte[] expectedK2 = { 0, 1, 0, 0, 0, 0, 1, 1 };
        assertEquals(Arrays.toString(expectedK1), Arrays.toString(app.k1));
        assertEquals(Arrays.toString(expectedK2), Arrays.toString(app.k2));
        byte[] ip = app.data.get("IP").clone();
        byte[] plainText0 = { 0, 1, 1, 1, 0, 0, 1, 0 };
        byte[] intialPermutation = permuteArray(plainText0, ip);
        byte[] r = new byte[4];
        for (int i = 4; i < 8; i++) {
            r[i - 4] = intialPermutation[i];
        }
        byte[] ep = app.data.get("EP").clone();
        byte[] exp = expansionPermutation(r, ep);
        byte[] xord = xor(exp, app.k1);
        byte[] expected = { 0, 1, 1, 0, 0, 1, 1, 1 };
        assertEquals(Arrays.toString(expected), Arrays.toString(xord));
        byte[] leftHalf = new byte[4];
        byte[] rightHalf = new byte[4];
        System.arraycopy(xord, 0, leftHalf, 0, 4);
        System.arraycopy(xord, 4, rightHalf, 0, 4);
        byte[] es0 = s0(leftHalf);
        byte[] expectedS0 = { 1, 0 };
        assertEquals(Arrays.toString(expectedS0), Arrays.toString(es0));
        byte[] es1 = s1(rightHalf);
        byte[] expectedS1 = { 1, 1 };
        assertEquals(Arrays.toString(expectedS1), Arrays.toString(es1));
        byte[] p4 = new byte[4];
        p4[0] = es0[0];
        p4[1] = es0[1];
        p4[2] = es1[0];
        p4[3] = es1[1];
        byte[] actualP4 = permuteArray(p4, app.data.get("P4").clone());
        byte[] expectedP4 = { 0, 1, 1, 1 };
        assertEquals(Arrays.toString(expectedP4), Arrays.toString(actualP4));
    }

    @Test
    void fkTest() {
        byte[] exampleFromDocument = { 1, 0, 1, 0, 0, 0, 0, 0, 1, 0 };
        app.KeyGeneration(exampleFromDocument);
        byte[] ip = app.data.get("IP").clone();
        byte[] plainText0 = { 0, 1, 1, 1, 0, 0, 1, 0 };
        byte[] intialPermutation = permuteArray(plainText0, ip);
        byte[] actualP4 = app.fk(intialPermutation, app.k1);
        byte[] expectedP4 = { 0, 1, 1, 1 };
        assertEquals(Arrays.toString(expectedP4), Arrays.toString(actualP4));
    }

    @Test
    void swTest() {
        byte[] eightBits = { 1, 0, 1, 0, 0, 0, 0, 0 };
        byte[] fourBits = { 1, 1, 1, 0 };
        byte[] actual = sw(fourBits, eightBits);
        byte[] expected = { 0, 0, 0, 0, 1, 1, 1, 0 };
        assertEquals(Arrays.toString(expected), Arrays.toString(actual));
    }

    @Test
    void encryptTest0() {
        byte[] rawKey0 = data.get("rawKey0");
        byte[] plainText0 = data.get("plainText0");
        byte[] cipherText0 = data.get("cipherText0");
        assertEquals(Arrays.toString(Encrypt(rawKey0, plainText0)), Arrays.toString(cipherText0));
    }

    @Test
    void encryptTest1() {
        byte[] rawKey1 = data.get("rawKey1");
        byte[] plainText1 = data.get("plainText1");
        byte[] cipherText1 = data.get("cipherText1");
        assertEquals(Arrays.toString(Encrypt(rawKey1, plainText1)), Arrays.toString(cipherText1));
    }

    @Test
    void encryptTest2() {
        byte[] rawKey2 = data.get("rawKey2");
        byte[] plainText2 = data.get("plainText2");
        byte[] cipherText2 = data.get("cipherText2");
        assertEquals(Arrays.toString(Encrypt(rawKey2, plainText2)), Arrays.toString(cipherText2));
    }

    @Test
    void encryptTest3() {
        byte[] rawKey3 = data.get("rawKey3");
        byte[] plainText3 = data.get("plainText3");
        byte[] cipherText3 = data.get("cipherText3");
        assertEquals(Arrays.toString(Decrypt(rawKey3, plainText3)), Arrays.toString(cipherText3));
    }

    @Test
    void decryptTest0() {
        byte[] rawKey0 = data.get("rawKey0");
        byte[] plainText0 = data.get("plainText0");
        byte[] cipherText0 = data.get("cipherText0");
        assertEquals(Arrays.toString(Decrypt(rawKey0, cipherText0)), Arrays.toString(plainText0));
    }

    @Test
    void decryptTest1() {
        byte[] rawKey1 = data.get("rawKey1");
        byte[] plainText1 = data.get("plainText1");
        byte[] cipherText1 = data.get("cipherText1");
        assertEquals(Arrays.toString(Decrypt(rawKey1, cipherText1)), Arrays.toString(plainText1));
    }

    @Test
    void decryptTest2() {
        byte[] rawKey2 = data.get("rawKey2");
        byte[] plainText2 = data.get("plainText2");
        byte[] cipherText2 = data.get("cipherText2");
        assertEquals(Arrays.toString(Decrypt(rawKey2, cipherText2)), Arrays.toString(plainText2));
    }

    @Test
    void decryptTest3() {
        byte[] rawKey3 = data.get("rawKey3");
        byte[] plainText3 = data.get("plainText3");
        byte[] cipherText3 = data.get("cipherText3");
        assertEquals(Arrays.toString(Decrypt(rawKey3, cipherText3)), Arrays.toString(plainText3));
    }
}
