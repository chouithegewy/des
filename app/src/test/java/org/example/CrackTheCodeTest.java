package org.example;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

class CrackTheCodeTest {
    @Test
    void encryptsCryptoGraphyWithCASCII() {
        assertEquals(
                "0110000111001010101101101111010011000101011101101111110001110111",
                CrackTheCode.encryptCASCIIWithSDES("CRYPTOGRAPHY", "0111001101"));
    }

    @Test
    void cracksMsg1() throws IOException {
        CrackTheCode.CrackResult result = CrackTheCode.crackSDES(Path.of("assets/msg1.txt"));

        assertEquals("1011110100", result.key1Bits());
        assertEquals(
                "WHOEVER THINKS HIS PROBLEM CAN BE SOLVED USING CRYPTOGRAPHY, DOESN'T UNDERSTAND HIS PROBLEM AND DOESN'T UNDERSTAND CRYPTOGRAPHY.  ATTRIBUTED BY ROGER NEEDHAM AND BUTLER LAMPSON TO EACH OTHER",
                result.plaintext());
    }

    @Test
    void cracksMsg2() throws IOException {
        CrackTheCode.CrackResult result = CrackTheCode.crackTripleSDES(Path.of("assets/msg2.txt"));

        assertEquals("1110000101", result.key1Bits());
        assertEquals("0101100011", result.key2Bits());
        assertEquals(
                "THERE ARE NO SECRETS BETTER KEPT THAN THE SECRETS THAT EVERYBODY GUESSES.",
                result.plaintext());
    }
}
