package org.example;

import java.util.Arrays;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import static org.example.App.Encrypt;

class AppTest {
    static HashMap<String, byte[]> data = new HashMap<>();

    @BeforeAll
    static void generateData() {
        App testApp = new App();
        data = testApp.data;
    }

    @Test
    void encryptTest() {
        byte[] rawKey0 = data.get("rawKey0");
        byte[] plainText0 = data.get("plainText0");
        byte[] cipherText0 = data.get("cipherText0");
        assertEquals(Encrypt(rawKey0, plainText0), cipherText0);
    }
}
