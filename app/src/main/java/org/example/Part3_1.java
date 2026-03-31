package org.example;

import java.util.List;
import java.util.Arrays;

import org.example.SDES;

class Part3_1 {
    Part3_1() {
    }

    static void part3() {
        SDES app = new SDES();
        List<byte[]> plaintextArrayOfBytes = app.part3("CRYPTOGRAPHY"); // binary ascii representation = "CRYPTOGRAPHY";
        byte[] rawkeyPt3 = { 0, 1, 1, 1, 0, 0, 1, 1, 0, 1 };
        for (byte[] p : plaintextArrayOfBytes) {
            System.out.println(Arrays.toString(SDES.Encrypt(rawkeyPt3, p)));
        }
    }

}
