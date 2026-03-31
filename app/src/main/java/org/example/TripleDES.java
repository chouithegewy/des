package org.example;

import org.example.SDES;

public class TripleDES {
    TripleDES() {
    }

    // E3DES(p) = EDES(k1,DDES(k2,EDES(k1, p)))
    public static byte[] E3SDES(byte[] k1, byte[] k2, byte[] p) {
        return SDES.Encrypt(k1, SDES.Decrypt(k2, SDES.Encrypt(k1, p)));
    }

    // D3DES(c) = DDES(k1,EDES(k2,DDES(k1, c)))
    public static byte[] D3SDES(byte[] k1, byte[] k2, byte[] c) {
        return SDES.Decrypt(k1, SDES.Encrypt(k2, SDES.Decrypt(k1, c)));
    }
}
