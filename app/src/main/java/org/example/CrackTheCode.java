package org.example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.IntStream;

public final class CrackTheCode {
    private static final int KEY_COUNT = 1 << 10;
    private static final String CASCII_ALPHABET = " ABCDEFGHIJKLMNOPQRSTUVWXYZ,?:.'";

    private static final int[] P10 = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };
    private static final int[] P8 = { 6, 3, 7, 4, 8, 5, 10, 9 };
    private static final int[] IP = { 2, 6, 3, 1, 4, 8, 5, 7 };
    private static final int[] IP_INVERSE = { 4, 1, 3, 5, 7, 2, 8, 6 };
    private static final int[] EP = { 4, 1, 2, 3, 2, 3, 4, 1 };
    private static final int[] P4 = { 2, 4, 3, 1 };

    private static final int[][] S0 = {
            { 1, 0, 3, 2 },
            { 3, 2, 1, 0 },
            { 0, 2, 1, 3 },
            { 3, 1, 3, 2 }
    };
    private static final int[][] S1 = {
            { 0, 1, 2, 3 },
            { 2, 0, 1, 3 },
            { 3, 0, 1, 0 },
            { 2, 1, 0, 3 }
    };

    private static final Set<String> COMMON_WORDS = Set.of(
            "A", "I", "THE", "OF", "AND", "TO", "IN", "IS", "YOU", "THAT", "IT", "HE", "WAS",
            "FOR", "ON", "ARE", "AS", "WITH", "HIS", "THEY", "BE", "AT", "ONE", "HAVE",
            "THIS", "FROM", "OR", "HAD", "BY", "BUT", "SOME", "WHAT", "THERE", "WE", "CAN",
            "OUT", "OTHER", "WERE", "ALL", "YOUR", "WHEN", "UP", "USE", "HOW", "SAID",
            "AN", "EACH", "SHE", "WHICH", "DO", "THEIR", "TIME", "IF", "WILL", "WAY",
            "ABOUT", "MANY", "THEN", "THEM", "WOULD", "LIKE", "SO", "THESE", "HER",
            "LONG", "MAKE", "THING", "SEE", "HIM", "TWO", "HAS", "MORE", "DAY", "COULD",
            "GO", "COME", "DID", "MY", "NO", "MOST", "WHO", "OVER", "KNOW", "THAN",
            "FIRST", "PEOPLE", "MAY", "DOWN", "BEEN", "NOW", "ANY", "NEW", "WORK",
            "TAKE", "GET", "MADE", "AFTER", "BACK", "ONLY", "GOOD", "ME", "GIVE", "OUR",
            "JUST", "GREAT", "THINK", "SAY", "HELP", "RIGHT", "OLD", "TOO", "SAME",
            "TELL", "DOES", "WANT", "WELL", "ALSO", "END", "PUT", "HERE", "MUST",
            "WHY", "AGAIN", "POINT", "WORLD", "SHOULD", "FOUND", "ANSWER", "STILL",
            "NEVER", "LAST", "BETWEEN", "SINCE", "START", "STORY", "LATE", "OPEN",
            "SEEM", "TOGETHER", "NEXT", "BOTH", "UNTIL", "SURE", "ENOUGH", "THOUGH",
            "FEEL", "TALK", "SOON", "COMPLETE", "QUESTION", "PROBLEM", "BEST", "BETTER",
            "TRUE", "DURING", "REMEMBER", "AGAINST", "PERSON", "NOTHING", "COURSE",
            "POSSIBLE", "LANGUAGE", "MESSAGE", "CRYPTOGRAPHY", "UNDERSTAND", "ATTRIBUTED",
            "ROGER", "NEEDHAM", "BUTLER", "LAMPSON", "SECRET", "SECRETS", "KEPT",
            "EVERYBODY", "GUESSES");

    private CrackTheCode() {
    }

    public static void main(String[] args) throws IOException {
        Path msg1Path = args.length > 0 ? Path.of(args[0]) : defaultAssetPath("msg1.txt");
        Path msg2Path = args.length > 1 ? Path.of(args[1]) : defaultAssetPath("msg2.txt");

        printProcess();

        BlockTables tables = buildBlockTables();
        String part1 = encryptCASCIIWithSDES("CRYPTOGRAPHY", "0111001101");
        CrackResult msg1 = crackSDES(readCiphertextBytes(msg1Path), tables);
        CrackResult msg2 = crackTripleSDES(readCiphertextBytes(msg2Path), tables);

        System.out.println();
        System.out.println("1) SDES(CASCII(\"CRYPTOGRAPHY\"), key 0111001101)");
        System.out.println(part1);
        System.out.println(groupBits(part1));

        System.out.println();
        System.out.println("2) " + msg1Path);
        System.out.println("Raw key: " + msg1.key1Bits());
        System.out.println("Plaintext: " + msg1.plaintext());

        System.out.println();
        System.out.println("3) " + msg2Path);
        System.out.println("Raw keys: " + msg2.key1Bits() + ", " + msg2.key2Bits());
        System.out.println("Plaintext: " + msg2.plaintext());
        System.out.println();
        System.out.println("TripleSDES brute force used " + ForkJoinPool.getCommonPoolParallelism()
                + " worker threads.");
    }

    public static String encryptCASCIIWithSDES(String plaintext, String rawKeyBits) {
        int rawKey = parseKey(rawKeyBits);
        int[] plaintextBits = casciiEncode(plaintext);
        KeySchedule schedule = keySchedule(rawKey);

        StringBuilder ciphertext = new StringBuilder(plaintextBits.length);
        for (int i = 0; i < plaintextBits.length; i += 8) {
            appendByteBits(ciphertext, encryptBlock(schedule, bitsToByte(plaintextBits, i)));
        }
        return ciphertext.toString();
    }

    public static CrackResult crackSDES(Path ciphertextPath) throws IOException {
        return crackSDES(readCiphertextBytes(ciphertextPath), buildBlockTables());
    }

    public static CrackResult crackTripleSDES(Path ciphertextPath) throws IOException {
        return crackTripleSDES(readCiphertextBytes(ciphertextPath), buildBlockTables());
    }

    public static int[] casciiEncode(String text) {
        String upper = text.toUpperCase(Locale.ROOT);
        int bitCount = upper.length() * 5;
        int paddedBitCount = bitCount + (8 - (bitCount % 8));
        int[] bits = new int[paddedBitCount];

        for (int charIndex = 0; charIndex < upper.length(); charIndex++) {
            char ch = upper.charAt(charIndex);
            int value = CASCII_ALPHABET.indexOf(ch);
            if (value < 0) {
                throw new IllegalArgumentException(
                        "CASCII supports only A-Z, space, comma, question mark, colon, period, and apostrophe: "
                                + ch);
            }
            for (int bit = 0; bit < 5; bit++) {
                bits[charIndex * 5 + bit] = (value >> bit) & 1;
            }
        }
        return bits;
    }

    public static String casciiDecode(int[] packedBytes) {
        int bitCount = packedBytes.length * 8;
        StringBuilder plaintext = new StringBuilder(bitCount / 5);
        for (int block = 0; block + 5 <= bitCount; block += 5) {
            int value = 0;
            for (int bit = 0; bit < 5; bit++) {
                value += bitAt(packedBytes, block + bit) << bit;
            }
            plaintext.append(CASCII_ALPHABET.charAt(value));
        }
        return plaintext.toString();
    }

    private static CrackResult crackSDES(int[] ciphertext, BlockTables tables) {
        return IntStream.range(0, KEY_COUNT)
                .parallel()
                .mapToObj(key -> scoreSDESKey(key, ciphertext, tables))
                .max(Comparator.comparingDouble(CrackResult::score))
                .orElseThrow();
    }

    private static CrackResult crackTripleSDES(int[] ciphertext, BlockTables tables) {
        return IntStream.range(0, KEY_COUNT)
                .parallel()
                .mapToObj(key1 -> bestTripleKey2ForKey1(key1, ciphertext, tables))
                .max(Comparator.comparingDouble(CrackResult::score))
                .orElseThrow();
    }

    private static CrackResult scoreSDESKey(int key, int[] ciphertext, BlockTables tables) {
        int[] plaintext = new int[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = tables.decrypt[key][ciphertext[i]] & 0xff;
        }

        String decoded = casciiDecode(plaintext);
        return new CrackResult(key, -1, englishScore(decoded), decoded);
    }

    private static CrackResult bestTripleKey2ForKey1(int key1, int[] ciphertext, BlockTables tables) {
        int[] firstDecrypt = new int[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            firstDecrypt[i] = tables.decrypt[key1][ciphertext[i]] & 0xff;
        }

        CrackResult best = null;
        int[] plaintext = new int[ciphertext.length];
        for (int key2 = 0; key2 < KEY_COUNT; key2++) {
            for (int i = 0; i < firstDecrypt.length; i++) {
                int middle = tables.encrypt[key2][firstDecrypt[i]] & 0xff;
                plaintext[i] = tables.decrypt[key1][middle] & 0xff;
            }

            String decoded = casciiDecode(plaintext);
            CrackResult candidate = new CrackResult(key1, key2, englishScore(decoded), decoded);
            if (best == null || candidate.score() > best.score()) {
                best = candidate;
            }
        }
        return best;
    }

    private static double englishScore(String text) {
        double score = 0.0;
        int spaces = count(text, ' ');
        score -= Math.abs(spaces - (text.length() / 6.0)) * 0.8;
        score -= countAny(text, "?:'") * 0.8;

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if ("ETAOINSHRDLU".indexOf(ch) >= 0) {
                score += 0.8;
            } else if (ch >= 'A' && ch <= 'Z') {
                score += 0.15;
            } else if (ch == ' ') {
                score += 1.3;
            } else if (ch == ',' || ch == '.') {
                score += 0.25;
            }
        }

        String padded = " " + text + " ";
        String[] commonPhrases = {
                " THE ", " OF ", " AND ", " TO ", " IN ", " IS ", " THAT ", " HIS ", " CAN ",
                " BE ", " BY ", " THERE ", " ARE ", " NO ", " THAN ", " TO EACH OTHER "
        };
        for (String phrase : commonPhrases) {
            score += countOccurrences(padded, phrase) * 14.0;
        }

        for (String token : text.split("[^A-Z]+")) {
            if (token.isEmpty()) {
                continue;
            }
            if (COMMON_WORDS.contains(token)) {
                score += 8.0 + Math.min(token.length(), 10);
            } else if (token.length() == 1) {
                score -= 1.5;
            } else {
                score -= Math.min(token.length(), 12) * 0.7;
                if (token.length() >= 4 && !hasVowel(token)) {
                    score -= 5.0;
                }
            }
        }
        return score;
    }

    private static BlockTables buildBlockTables() {
        byte[][] encrypt = new byte[KEY_COUNT][256];
        byte[][] decrypt = new byte[KEY_COUNT][256];

        for (int key = 0; key < KEY_COUNT; key++) {
            KeySchedule schedule = keySchedule(key);
            for (int block = 0; block < 256; block++) {
                encrypt[key][block] = (byte) encryptBlock(schedule, block);
                decrypt[key][block] = (byte) decryptBlock(schedule, block);
            }
        }
        return new BlockTables(encrypt, decrypt);
    }

    private static int encryptBlock(KeySchedule schedule, int plaintextByte) {
        int[] ip = permute(toBits(plaintextByte, 8), IP);
        int[] p4Round1 = fk(ip, schedule.k1());
        int[] round1Left = xor(p4Round1, leftHalf(ip));
        int[] switched = switchHalves(round1Left, ip);

        int[] p4Round2 = fk(switched, schedule.k2());
        int[] round2Left = xor(p4Round2, leftHalf(switched));
        return fromBits(permute(join(round2Left, rightHalf(switched)), IP_INVERSE));
    }

    private static int decryptBlock(KeySchedule schedule, int ciphertextByte) {
        int[] ip = permute(toBits(ciphertextByte, 8), IP);
        int[] p4Round1 = fk(ip, schedule.k2());
        int[] round1Left = xor(p4Round1, leftHalf(ip));
        int[] switched = switchHalves(round1Left, ip);

        int[] p4Round2 = fk(switched, schedule.k1());
        int[] round2Left = xor(p4Round2, leftHalf(switched));
        return fromBits(permute(join(round2Left, rightHalf(switched)), IP_INVERSE));
    }

    private static KeySchedule keySchedule(int rawKey) {
        int[] p10 = permute(toBits(rawKey, 10), P10);
        int[] shiftedOnce = shiftBothHalves(p10, 1);
        int[] k1 = permute(shiftedOnce, P8);
        int[] k2 = permute(shiftBothHalves(shiftedOnce, 2), P8);
        return new KeySchedule(k1, k2);
    }

    private static int[] fk(int[] input, int[] key) {
        int[] expanded = permute(rightHalf(input), EP);
        int[] mixed = xor(expanded, key);
        int[] sBoxOutput = join(sBox(S0, slice(mixed, 0, 4)), sBox(S1, slice(mixed, 4, 8)));
        return permute(sBoxOutput, P4);
    }

    private static int[] sBox(int[][] box, int[] bits) {
        int row = (bits[0] << 1) | bits[3];
        int column = (bits[1] << 1) | bits[2];
        int value = box[row][column];
        return new int[] { (value >> 1) & 1, value & 1 };
    }

    private static int[] permute(int[] source, int[] permutation) {
        int[] output = new int[permutation.length];
        for (int i = 0; i < permutation.length; i++) {
            output[i] = source[permutation[i] - 1];
        }
        return output;
    }

    private static int[] shiftBothHalves(int[] bits, int shift) {
        return join(shift(slice(bits, 0, bits.length / 2), shift),
                shift(slice(bits, bits.length / 2, bits.length), shift));
    }

    private static int[] shift(int[] bits, int shift) {
        int[] output = new int[bits.length];
        for (int i = 0; i < bits.length; i++) {
            output[Math.floorMod(i - shift, bits.length)] = bits[i];
        }
        return output;
    }

    private static int[] switchHalves(int[] newRight, int[] original) {
        return join(rightHalf(original), newRight);
    }

    private static int[] xor(int[] left, int[] right) {
        int[] output = new int[left.length];
        for (int i = 0; i < left.length; i++) {
            output[i] = left[i] ^ right[i];
        }
        return output;
    }

    private static int[] leftHalf(int[] bits) {
        return slice(bits, 0, bits.length / 2);
    }

    private static int[] rightHalf(int[] bits) {
        return slice(bits, bits.length / 2, bits.length);
    }

    private static int[] slice(int[] bits, int start, int end) {
        int[] output = new int[end - start];
        System.arraycopy(bits, start, output, 0, output.length);
        return output;
    }

    private static int[] join(int[] left, int[] right) {
        int[] output = new int[left.length + right.length];
        System.arraycopy(left, 0, output, 0, left.length);
        System.arraycopy(right, 0, output, left.length, right.length);
        return output;
    }

    private static int[] toBits(int value, int width) {
        int[] bits = new int[width];
        for (int i = 0; i < width; i++) {
            bits[i] = (value >> (width - 1 - i)) & 1;
        }
        return bits;
    }

    private static int fromBits(int[] bits) {
        int value = 0;
        for (int bit : bits) {
            value = (value << 1) | bit;
        }
        return value;
    }

    private static int bitsToByte(int[] bits, int start) {
        int value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 1) | bits[start + i];
        }
        return value;
    }

    private static int bitAt(int[] packedBytes, int bitIndex) {
        int value = packedBytes[bitIndex / 8];
        int shift = 7 - (bitIndex % 8);
        return (value >> shift) & 1;
    }

    private static int parseKey(String rawKeyBits) {
        if (!rawKeyBits.matches("[01]{10}")) {
            throw new IllegalArgumentException("Raw keys must be exactly 10 bits: " + rawKeyBits);
        }
        int value = 0;
        for (int i = 0; i < rawKeyBits.length(); i++) {
            value = (value << 1) | (rawKeyBits.charAt(i) - '0');
        }
        return value;
    }

    private static int[] readCiphertextBytes(Path path) throws IOException {
        Path resolvedPath = resolvePath(path);
        String bits = Files.readString(resolvedPath, StandardCharsets.UTF_8).replaceAll("\\s+", "");
        if (bits.length() % 8 != 0) {
            throw new IllegalArgumentException("Ciphertext bit length must be a multiple of 8: " + bits.length());
        }

        int[] bytes = new int[bits.length() / 8];
        for (int i = 0; i < bytes.length; i++) {
            int value = 0;
            for (int bit = 0; bit < 8; bit++) {
                char ch = bits.charAt(i * 8 + bit);
                if (ch != '0' && ch != '1') {
                    throw new IllegalArgumentException("Ciphertext contains a non-bit character: " + ch);
                }
                value = (value << 1) | (ch - '0');
            }
            bytes[i] = value;
        }
        return bytes;
    }

    private static Path defaultAssetPath(String fileName) {
        Path assetPath = resolvePath(Path.of("assets", fileName));
        if (Files.exists(assetPath)) {
            return assetPath;
        }
        return resolvePath(Path.of(fileName));
    }

    private static Path resolvePath(Path path) {
        if (Files.exists(path)) {
            return path;
        }

        Path fromParent = Path.of("..").resolve(path).normalize();
        if (Files.exists(fromParent)) {
            return fromParent;
        }

        return path;
    }

    private static void appendByteBits(StringBuilder builder, int value) {
        for (int bit = 7; bit >= 0; bit--) {
            builder.append((value >> bit) & 1);
        }
    }

    private static String keyToBits(int key) {
        String bits = Integer.toBinaryString(key);
        return "0".repeat(10 - bits.length()) + bits;
    }

    private static String groupBits(String bits) {
        StringBuilder grouped = new StringBuilder(bits.length() + bits.length() / 8);
        for (int i = 0; i < bits.length(); i++) {
            if (i > 0 && i % 8 == 0) {
                grouped.append(' ');
            }
            grouped.append(bits.charAt(i));
        }
        return grouped.toString();
    }

    private static int count(String text, char ch) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == ch) {
                count++;
            }
        }
        return count;
    }

    private static int countAny(String text, String chars) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (chars.indexOf(text.charAt(i)) >= 0) {
                count++;
            }
        }
        return count;
    }

    private static int countOccurrences(String text, String needle) {
        int count = 0;
        int index = text.indexOf(needle);
        while (index >= 0) {
            count++;
            index = text.indexOf(needle, index + needle.length());
        }
        return count;
    }

    private static boolean hasVowel(String token) {
        for (int i = 0; i < token.length(); i++) {
            if ("AEIOUY".indexOf(token.charAt(i)) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static void printProcess() {
        System.out.println("Process");
        System.out.println("CASCII maps space=0, A=1, ..., Z=26, comma=27, question=28, colon=29,");
        System.out.println("period=30, apostrophe=31. Each character is stored as five bits with the");
        System.out.println("least significant bit first, then zero-padded to an 8-bit SDES block boundary.");
        System.out.println("The padding follows the course CASCII code: append 8 - remainder zero bits.");
        System.out.println("To crack SDES, try every 10-bit raw key, decrypt each 8-bit block, decode CASCII,");
        System.out.println("and keep the candidate with the strongest English score.");
        System.out.println("To crack TripleSDES, precompute SDES encrypt/decrypt byte tables for every key,");
        System.out.println("then search all 1024 x 1024 key pairs in parallel using D(k1), E(k2), D(k1).");
    }

    private record KeySchedule(int[] k1, int[] k2) {
    }

    private record BlockTables(byte[][] encrypt, byte[][] decrypt) {
    }

    public record CrackResult(int key1, int key2, double score, String plaintext) {
        public String key1Bits() {
            return keyToBits(key1);
        }

        public String key2Bits() {
            if (key2 < 0) {
                return "";
            }
            return keyToBits(key2);
        }
    }
}
