package org.example;

import java.util.Arrays;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import static org.example.App.Encrypt;
import static org.example.App.leftShift;
import static org.example.App.permuteArray;

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
    void encryptTest() {
        byte[] rawKey0 = data.get("rawKey0");
        byte[] plainText0 = data.get("plainText0");
        byte[] cipherText0 = data.get("cipherText0");
        assertEquals(Encrypt(rawKey0, plainText0), cipherText0);
    }
}
