import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.example.SDES;

public class CrackTheCode {

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
                        byte[] plaintext = SDES.Decrypt(rawkey, ciphertext);
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
}
