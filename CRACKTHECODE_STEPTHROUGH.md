# CrackTheCode Step-Through

Generated on 2026-05-03 for `app/src/main/java/org/example/CrackTheCode.java`.

This document walks through what `CrackTheCode` does when it runs, why each step exists, and what the important implementation tradeoffs are.

## 1. High-Level Purpose

`CrackTheCode` solves the Part 3 tasks:

1. Encode `CRYPTOGRAPHY` in CASCII and encrypt it with SDES key `0111001101`.
2. Crack `assets/msg1.txt`, which is encrypted with single SDES.
3. Crack `assets/msg2.txt`, which is encrypted with TripleSDES.

The implementation is intentionally self-contained. It does not call the public `SDES` or `TripleDES` methods during the brute-force search. Instead, it reimplements the same SDES block logic with integer arrays and precomputed byte lookup tables so the repeated search is much faster.

## 2. Constants And Data Model

Relevant code: lines 14-57.

`KEY_COUNT = 1 << 10` means there are `1024` possible raw SDES keys. This is small enough to exhaustively search.

`CASCII_ALPHABET = " ABCDEFGHIJKLMNOPQRSTUVWXYZ,?:.'"` defines the 32-character alphabet. Because 32 values fit exactly in 5 bits, each CASCII character is represented as a 5-bit value.

The permutation arrays are the SDES wiring tables:

- `P10` and `P8` generate the two 8-bit round keys from a 10-bit raw key.
- `IP` and `IP_INVERSE` wrap each 8-bit block before and after the two Feistel rounds.
- `EP` expands the right 4 bits of a round input to 8 bits.
- `P4` permutes the 4-bit S-box output.

`S0` and `S1` are the two SDES substitution boxes. `COMMON_WORDS` is not cryptographic data; it is part of the English scoring heuristic used to identify the most plausible plaintext.

Analysis: the code treats ciphertext as bytes, keys as integers from `0` through `1023`, and plaintext as uppercase CASCII. This makes the search compact and avoids object-heavy `byte[]` calls inside the hot loops.

## 3. Program Entry Point

Relevant code: lines 62-90.

The `main` method follows this sequence:

1. Resolve `msg1.txt` and `msg2.txt`.
2. Print a short process summary.
3. Build SDES lookup tables for every possible key.
4. Encrypt `CRYPTOGRAPHY` with SDES.
5. Crack the single-SDES message.
6. Crack the TripleSDES message.
7. Print the ciphertext, recovered key or keys, plaintexts, and common-pool worker count.

Default paths are resolved by checking `assets/<name>`, then `<name>`, with a parent-directory fallback. This lets the same class run from the repo root or from a submitted folder.

## 4. Building The SDES Lookup Tables

Relevant code: lines 241-253.

`buildBlockTables()` creates two arrays:

- `encrypt[key][block]`
- `decrypt[key][block]`

For each of 1024 keys and each of 256 byte values, the method computes SDES encryption and decryption once. That is `1024 x 256 x 2 = 524288` block transformations.

Analysis: this is the main performance optimization. TripleSDES cracking needs to evaluate every key pair, so a table lookup is much cheaper than recomputing SDES rounds for every byte of every candidate. The tables are small: about 512 KiB of raw byte data, plus Java array overhead.

## 5. CASCII Encoding

Relevant code: lines 112-131.

`casciiEncode`:

1. Converts text to uppercase.
2. Maps each character to its index in the 32-character CASCII alphabet.
3. Emits 5 bits per character, least-significant bit first.
4. Pads with zero bits until the stream reaches an 8-bit SDES block boundary.

For `CRYPTOGRAPHY`, the per-character CASCII values are:

```text
C =  3 -> 11000
R = 18 -> 01001
Y = 25 -> 10011
P = 16 -> 00001
T = 20 -> 00101
O = 15 -> 11110
G =  7 -> 11100
R = 18 -> 01001
A =  1 -> 10000
P = 16 -> 00001
H =  8 -> 00010
Y = 25 -> 10011
```

Those 60 data bits are padded to 64 bits, producing eight SDES input bytes:

```text
11000010 01100110 00010010 11111011 10001001 10000000 01000101 00110000
```

Analysis: CASCII bit order is easy to get wrong because each 5-bit character is little-endian within the character, while SDES byte operations consume 8-bit blocks in normal left-to-right order.

## 6. CASCII Decoding

Relevant code: lines 133-144 and 377-381.

`casciiDecode` does the reverse:

1. Treat the decrypted bytes as one continuous bit stream.
2. Read 5 bits at a time.
3. Interpret those 5 bits least-significant bit first.
4. Use the value as an index into `CASCII_ALPHABET`.
5. Ignore any final leftover bits that do not form a complete 5-bit character.

For the bundled assets:

- `msg1.txt` has 952 bits, or 119 encrypted bytes, and decodes to 190 CASCII characters.
- `msg2.txt` has 368 bits, or 46 encrypted bytes, and decodes to 73 CASCII characters.

Analysis: the decoder assumes the plaintext was padded exactly for SDES blocks. It does not store an original plaintext length; it simply drops incomplete trailing bits.

## 7. SDES Key Schedule

Relevant code: lines 277-282.

`keySchedule` derives `k1` and `k2` from a 10-bit raw key:

1. Convert the raw key integer to 10 bits.
2. Apply `P10`.
3. Left-shift both 5-bit halves by 1.
4. Apply `P8` to produce `k1`.
5. Starting from the shifted-once state, left-shift both halves by 2 more.
6. Apply `P8` to produce `k2`.

For raw key `0111001101`:

```text
raw key: 0111001101
P10:     1011110010
LS-1:    0111100101
k1:      01011110
LS-2:    1110110100
k2:      11001100
```

Analysis: the implementation stores subkeys as `int[]` bit arrays. That is not the most memory-dense representation, but subkeys are computed only when tables are built, so clarity wins here.

## 8. SDES Block Encryption

Relevant code: lines 255-264.

`encryptBlock` performs the standard two-round SDES Feistel structure:

1. Convert an 8-bit byte to an 8-bit array.
2. Apply `IP`.
3. Run `fk` with `k1`.
4. XOR the `fk` output into the left half.
5. Switch halves.
6. Run `fk` with `k2`.
7. XOR the second `fk` output into the left half.
8. Join the final halves.
9. Apply `IP_INVERSE`.
10. Convert the resulting bits back to an integer byte.

Concrete trace for the first CASCII byte of `CRYPTOGRAPHY`:

```text
plaintext byte: 11000010
after IP:       10010001
left/right:     1001 / 0001

round 1 with k1 = 01011110
EP(right):      10000010
XOR k1:         11011100
S-box output:   1101
P4:             1101
new left:       0100
after switch:   00010100

round 2 with k2 = 11001100
EP(right):      00101000
XOR k2:         11100100
S-box output:   1110
P4:             1011
new left:       1010
before IP^-1:   10100100
cipher byte:    01100001
```

That `01100001` byte is the first byte of the final Part 1 ciphertext.

## 9. SDES Block Decryption

Relevant code: lines 266-275.

`decryptBlock` mirrors `encryptBlock`, except it uses `k2` in the first round and `k1` in the second round. This works because SDES is a Feistel cipher.

Analysis: keeping encryption and decryption as separate methods makes the table generation explicit and avoids passing a mode flag into a hot path.

## 10. The Round Function `fk`

Relevant code: lines 285-297.

`fk`:

1. Takes the right half of the 8-bit round input.
2. Applies expansion permutation `EP`, turning 4 bits into 8.
3. XORs the expanded bits with the round key.
4. Splits the result into two 4-bit halves.
5. Sends the left half through `S0` and the right half through `S1`.
6. Joins the two 2-bit S-box results into 4 bits.
7. Applies `P4`.

`sBox` uses the first and fourth bits as the row and the middle two bits as the column.

Analysis: this is the only nonlinear part of SDES. Everything else is permutation, shifting, or XOR.

## 11. Part 1: Encrypting `CRYPTOGRAPHY`

Relevant code: lines 92-102.

`encryptCASCIIWithSDES("CRYPTOGRAPHY", "0111001101")`:

1. Parses the 10-bit raw key.
2. CASCII-encodes the plaintext into padded bits.
3. Builds the two SDES round keys.
4. Encrypts each 8-bit block.
5. Appends each encrypted block as eight printed bits.

Observed result:

```text
0110000111001010101101101111010011000101011101101111110001110111
01100001 11001010 10110110 11110100 11000101 01110110 11111100 01110111
```

Analysis: this result is covered by `CrackTheCodeTest.encryptsCryptoGraphyWithCASCII`.

## 12. Part 2: Cracking Single SDES

Relevant code: lines 104-106, 146-152, and 162-170.

`crackSDES`:

1. Reads the ciphertext file into 8-bit integer blocks.
2. Searches all keys from `0` to `1023` in parallel.
3. For each key, decrypts every ciphertext byte through `tables.decrypt[key][byte]`.
4. Decodes the candidate bytes as CASCII.
5. Scores the decoded text as English.
6. Returns the candidate with the highest score.

For `assets/msg1.txt`, the search examines 1024 candidate keys and 119 encrypted bytes per candidate. That is 121856 byte decryption lookups, plus decoding and scoring.

Observed result:

```text
raw key:   1011110100
plaintext: WHOEVER THINKS HIS PROBLEM CAN BE SOLVED USING CRYPTOGRAPHY, DOESN'T UNDERSTAND HIS PROBLEM AND DOESN'T UNDERSTAND CRYPTOGRAPHY.  ATTRIBUTED BY ROGER NEEDHAM AND BUTLER LAMPSON TO EACH OTHER
```

Analysis: because every key is searched, the key recovery is exhaustive. The only heuristic part is deciding which decrypted candidate is the right one; for this message, the English score cleanly identifies the plaintext.

## 13. Part 3: Cracking TripleSDES

Relevant code: lines 108-110, 154-160, and 172-193.

The project's TripleSDES definition is:

```text
Encrypt: E(k1, D(k2, E(k1, plaintext)))
Decrypt: D(k1, E(k2, D(k1, ciphertext)))
```

`crackTripleSDES` searches all `1024 x 1024 = 1048576` key pairs:

1. Parallelize over `key1`.
2. For each `key1`, precompute `firstDecrypt = D(key1, ciphertext)` for every ciphertext byte.
3. For each possible `key2`, compute `E(key2, firstDecryptByte)`.
4. Finish with `D(key1, middleByte)`.
5. Decode the candidate bytes as CASCII.
6. Score the candidate as English.
7. Keep the best `key2` for that `key1`.
8. Across all `key1` values, return the best overall result.

For `assets/msg2.txt`, there are 46 encrypted bytes. The inner TripleSDES search performs about `1024 x 1024 x 46 x 2 = 96468992` hot-loop table lookups, plus the first-decrypt pass and scoring.

Observed result:

```text
raw keys:  1110000101, 0101100011
plaintext: THERE ARE NO SECRETS BETTER KEPT THAN THE SECRETS THAT EVERYBODY GUESSES.
```

Analysis: this brute force is feasible because SDES keys are only 10 bits. The lookup tables turn each block operation into array indexing, which keeps the million-pair search practical.

## 14. English Scoring

Relevant code: lines 195-239 and 459-496.

`englishScore` rewards and penalizes candidate plaintexts:

- Penalizes an unusual number of spaces.
- Penalizes heavy use of `?`, `:`, and apostrophe.
- Rewards common English letters such as `E`, `T`, `A`, `O`, `I`, and `N`.
- Rewards spaces, commas, and periods.
- Strongly rewards common phrases such as ` THE `, ` OF `, and ` TO EACH OTHER `.
- Rewards words in `COMMON_WORDS`.
- Penalizes unknown words, one-letter nonwords, and longer words with no vowels.

Analysis: this is a heuristic, not a proof. It is appropriate here because the assignment messages are natural English and the exhaustive keyspace is small. For very short messages or non-English plaintext, the best score could be wrong.

## 15. Input Validation And Path Handling

Relevant code: lines 383-435.

`parseKey` accepts only exactly ten `0` or `1` characters.

`readCiphertextBytes`:

1. Resolves the path.
2. Reads the file as UTF-8.
3. Removes whitespace.
4. Requires the remaining bit length to be a multiple of 8.
5. Requires every remaining character to be `0` or `1`.
6. Packs each 8-bit group into an integer byte.

Analysis: this catches malformed ciphertext early. A missing path is allowed to fall through to `Files.readString`, which will raise the normal file-not-found exception.

## 16. Records And Result Formatting

Relevant code: lines 510-527.

`KeySchedule` stores the two subkeys. `BlockTables` stores the encryption and decryption lookup tables. `CrackResult` stores the recovered key or keys, score, and plaintext.

`CrackResult.key1Bits()` and `key2Bits()` convert integer keys back to zero-padded 10-bit strings for display.

Analysis: using records keeps result passing simple and immutable. The `key2` value is `-1` for single-SDES results.

## 17. Important Caveats

1. `casciiEncode` always appends `8 - remainder` padding bits. If the CASCII bit length is already a multiple of 8, that means it appends a full extra byte of zero padding. The printed process says this is intentional because it follows the course CASCII code.
2. `casciiDecode` does not know the original message length. It decodes all complete 5-bit groups available after decryption.
3. The brute-force search is exhaustive over the keyspace, but the final selection depends on the English scorer.
4. Parallel stream tie-breaking is not important for the provided assets, but equal-scoring candidates would not be a strong basis for confidence.
5. The TripleSDES implementation uses the course two-key EDE pattern with `k1` reused on the outside, not a three-independent-key variant.

## 18. Verification

The JUnit tests pass:

```text
BUILD SUCCESSFUL
3 actionable tasks: 3 up-to-date
```

The program output was also verified by running the compiled class directly:

```text
1) SDES(CASCII("CRYPTOGRAPHY"), key 0111001101)
0110000111001010101101101111010011000101011101101111110001110111
01100001 11001010 10110110 11110100 11000101 01110110 11111100 01110111

2) assets/msg1.txt
Raw key: 1011110100
Plaintext: WHOEVER THINKS HIS PROBLEM CAN BE SOLVED USING CRYPTOGRAPHY, DOESN'T UNDERSTAND HIS PROBLEM AND DOESN'T UNDERSTAND CRYPTOGRAPHY.  ATTRIBUTED BY ROGER NEEDHAM AND BUTLER LAMPSON TO EACH OTHER

3) assets/msg2.txt
Raw keys: 1110000101, 0101100011
Plaintext: THERE ARE NO SECRETS BETTER KEPT THAN THE SECRETS THAT EVERYBODY GUESSES.
```

`gradlew run` failed in this environment with a Gradle startup issue: `Could not determine a usable wildcard IP for this machine`. Running the compiled class directly did not hit that Gradle issue.
