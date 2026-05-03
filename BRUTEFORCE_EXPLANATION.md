# Brute Force And CASCII Explanation

This file explains how `CrackTheCode.java` solves Part 3. It is written for the four-file submission version:

- `CrackTheCode.java`
- `Part3.java`
- `SDES.java`
- `TripleDES.java`

The runnable solver is `org.example.CrackTheCode`. `org.example.Part3` is a small wrapper that calls it.

## Whole Process

The assignment has three tasks:

1. Encode the CASCII plaintext `CRYPTOGRAPHY` with SDES key `0111001101`.
2. Crack `msg1.txt`, which was encrypted with one SDES key.
3. Crack `msg2.txt`, which was encrypted with two-key TripleSDES.

The solver does this in five stages:

1. Convert plaintext to CASCII bits when needed.
2. Encrypt or decrypt SDES 8-bit blocks.
3. Precompute SDES byte lookup tables for every possible 10-bit key.
4. Try every possible key, or every possible key pair, and decode each candidate plaintext as CASCII.
5. Score each decoded candidate as English and keep the best result.

The search space is small enough to brute force:

- SDES has a 10-bit raw key, so there are `2^10 = 1024` keys.
- Two-key TripleSDES has two 10-bit raw keys, so there are `2^10 * 2^10 = 1,048,576` key pairs.

The TripleSDES brute force is made fast by precomputing one-byte SDES encryption and decryption tables. After that, testing one TripleSDES key pair does not run all SDES permutations and S-boxes again. It only does array lookups.

## CASCII Encoding

CASCII is a 5-bit character encoding. It can represent exactly 32 symbols:

```text
0  = space
1  = A
2  = B
...
26 = Z
27 = ,
28 = ?
29 = :
30 = .
31 = '
```

The important detail is bit order. The original course `CASCII.java` stores each 5-bit character least-significant-bit first.

For example:

```text
C = 3 decimal = 00011 binary in normal 5-bit order
```

But CASCII stores those five bits from least significant to most significant:

```text
C -> 1 1 0 0 0
```

Another example:

```text
R = 18 decimal = 10010 binary in normal 5-bit order
R -> 0 1 0 0 1 in CASCII bit-array order
```

The plaintext `CRYPTOGRAPHY` has 12 characters. Each character is 5 bits:

```text
12 * 5 = 60 bits
```

SDES encrypts 8-bit blocks, so the CASCII bit string must be padded to a multiple of 8. The course CASCII code pads by appending:

```text
8 - (bitCount % 8)
```

zero bits. For `CRYPTOGRAPHY`, the remainder is 4, so 4 zero bits are appended:

```text
60 + 4 = 64 bits
```

That is why the answer to part 1 is 64 bits long.

## SDES And TripleSDES Direction

The solver follows the same SDES rules as the existing project:

- raw key length: 10 bits
- generated round keys: `k1` and `k2`, each 8 bits
- block size: 8 bits
- encryption round order: `k1`, then `k2`
- decryption round order: `k2`, then `k1`

TripleSDES is two-key EDE mode:

```text
Encrypt3(k1, k2, plaintext) = Encrypt(k1, Decrypt(k2, Encrypt(k1, plaintext)))
Decrypt3(k1, k2, ciphertext) = Decrypt(k1, Encrypt(k2, Decrypt(k1, ciphertext)))
```

The brute force for `msg2.txt` therefore tests each key pair with:

```text
D(k1), E(k2), D(k1)
```

on every ciphertext byte.

## Why English Scoring Is Needed

For regular ASCII plaintext, many wrong keys can be rejected because they produce non-printable bytes. CASCII is different. Every 5-bit value from 0 to 31 is valid CASCII, so almost every wrong decryption still decodes to some uppercase letters, spaces, or punctuation.

The solver therefore scores each candidate by how English-like it looks. It rewards:

- common letters such as `E`, `T`, `A`, `O`, `I`, `N`
- normal-looking spaces
- common words such as `THE`, `OF`, `AND`, `CRYPTOGRAPHY`, `SECRETS`
- common phrases such as ` THE ` and ` TO EACH OTHER `

It penalizes:

- too many unusual punctuation marks
- single-letter words other than `A` and `I`
- long tokens that are not in the common-word list
- long tokens with no vowel

The correct plaintext scores much higher than the random-looking wrong decryptions.

## Precomputed Tables

The method `buildBlockTables()` constructs two tables:

```java
byte[][] encrypt = new byte[1024][256];
byte[][] decrypt = new byte[1024][256];
```

The first index is the 10-bit raw key, treated as an integer from 0 to 1023. The second index is one 8-bit block, treated as an integer from 0 to 255.

For example:

```java
encrypt[key][block]
```

means:

```text
SDES encrypt one byte called block with raw key called key
```

and:

```java
decrypt[key][block]
```

means:

```text
SDES decrypt one byte called block with raw key called key
```

This costs:

```text
1024 keys * 256 blocks * 2 directions = 524,288 SDES block computations
```

After the tables exist, every later decrypt/encrypt operation is just an array lookup.

The memory cost is small:

```text
1024 * 256 bytes * 2 tables = 524,288 bytes
```

plus Java array overhead.

## SDES Brute Force

For `msg1.txt`, the solver tries all 1024 possible SDES raw keys.

For each key:

1. Decrypt each ciphertext byte using `tables.decrypt[key][cipherByte]`.
2. Pack the resulting bytes back into one bit stream.
3. Decode the bit stream as CASCII, using 5-bit chunks.
4. Score the resulting string as English.
5. Keep the candidate with the highest score.

For the given `msg1.txt`, the winner is:

```text
key: 1011110100
plaintext:
WHOEVER THINKS HIS PROBLEM CAN BE SOLVED USING CRYPTOGRAPHY, DOESN'T UNDERSTAND HIS PROBLEM AND DOESN'T UNDERSTAND CRYPTOGRAPHY.  ATTRIBUTED BY ROGER NEEDHAM AND BUTLER LAMPSON TO EACH OTHER
```

## TripleSDES Brute Force

For `msg2.txt`, the solver tries every pair:

```text
key1 = 0..1023
key2 = 0..1023
```

That is 1,048,576 key pairs.

For each pair, the decryption formula is:

```text
plaintext = D(k1, E(k2, D(k1, ciphertext)))
```

Using tables, one byte is decrypted like this:

```java
int first = decrypt[key1][cipherByte] & 0xff;
int middle = encrypt[key2][first] & 0xff;
int plain = decrypt[key1][middle] & 0xff;
```

The outer loop over `key1` is parallelized with Java parallel streams:

```java
IntStream.range(0, KEY_COUNT).parallel()
```

Each worker thread receives some `key1` values. For each assigned `key1`, it searches all 1024 `key2` values and returns the best candidate for that `key1`. The main stream then chooses the best candidate across all `key1` values.

For the given `msg2.txt`, the winner is:

```text
key1: 1110000101
key2: 0101100011
plaintext:
THERE ARE NO SECRETS BETTER KEPT THAN THE SECRETS THAT EVERYBODY GUESSES.
```

## Method-by-Method Explanation

### `main(String[] args)`

This is the main program.

It chooses the two message-file paths. If command-line arguments are provided, argument 0 is used for `msg1.txt` and argument 1 is used for `msg2.txt`. If no arguments are provided, it searches for default files.

It then:

1. Prints the process explanation.
2. Builds SDES byte tables with `buildBlockTables()`.
3. Computes part 1 with `encryptCASCIIWithSDES("CRYPTOGRAPHY", "0111001101")`.
4. Cracks `msg1.txt` with `crackSDES(...)`.
5. Cracks `msg2.txt` with `crackTripleSDES(...)`.
6. Prints all answers.

The tables are built once in `main` and reused for both cracking tasks.

### `encryptCASCIIWithSDES(String plaintext, String rawKeyBits)`

This method solves part 1.

It:

1. Parses the 10-bit key string into an integer using `parseKey`.
2. Converts the plaintext string to CASCII bits using `casciiEncode`.
3. Builds the SDES round keys using `keySchedule`.
4. Splits the CASCII bit stream into 8-bit blocks.
5. Encrypts each block using `encryptBlock`.
6. Appends each encrypted byte to a final ciphertext bit string.

The returned string is the final SDES ciphertext as zeros and ones.

### `crackSDES(Path ciphertextPath)`

This is a convenience method for callers and tests.

It:

1. Reads the ciphertext file with `readCiphertextBytes`.
2. Builds SDES byte tables with `buildBlockTables`.
3. Calls the private table-based `crackSDES` method.

### `crackTripleSDES(Path ciphertextPath)`

This is the TripleSDES convenience method for callers and tests.

It:

1. Reads the ciphertext file.
2. Builds SDES byte tables.
3. Calls the private table-based `crackTripleSDES` method.

### `casciiEncode(String text)`

This converts normal text to a CASCII bit array.

For each character:

1. Convert to uppercase.
2. Look up the character in `CASCII_ALPHABET`.
3. Store its 5-bit value least-significant-bit first.

For example, if the CASCII value is 18:

```text
18 decimal = 10010 normal binary
stored bits = 0, 1, 0, 0, 1
```

After all characters are encoded, the bit array is padded to a multiple of 8 using the same padding rule as the original course code.

### `casciiDecode(int[] packedBytes)`

This converts decrypted SDES bytes back to a string.

The method treats the byte array as one continuous bit stream. It then reads 5 bits at a time. For each 5-bit group:

1. Read the bits in CASCII order.
2. Convert them back to a value from 0 to 31.
3. Use that value as an index into `CASCII_ALPHABET`.

Any leftover bits that do not make a full 5-bit character are ignored.

### `crackSDES(int[] ciphertext, BlockTables tables)`

This is the real SDES brute-force loop.

It uses:

```java
IntStream.range(0, KEY_COUNT).parallel()
```

to test all 1024 raw keys. Each key is passed to `scoreSDESKey`. The stream returns the candidate with the maximum English score.

Parallelism is not strictly necessary for 1024 keys, but it keeps the approach consistent with the TripleSDES search.

### `crackTripleSDES(int[] ciphertext, BlockTables tables)`

This is the real TripleSDES brute-force loop.

It parallelizes the outer loop over `key1`. Each worker calls `bestTripleKey2ForKey1`, which searches all `key2` values for that one `key1`.

The output of each worker is one best candidate for its assigned `key1`. The stream then returns the highest-scoring candidate across all workers.

This layout avoids shared mutable state. Each worker uses local arrays and returns a `CrackResult`.

### `scoreSDESKey(int key, int[] ciphertext, BlockTables tables)`

This method tests one SDES key.

It:

1. Allocates a plaintext byte array the same length as the ciphertext.
2. Decrypts every byte with `tables.decrypt[key][ciphertext[i]]`.
3. Decodes the resulting bytes with `casciiDecode`.
4. Scores the decoded text with `englishScore`.
5. Returns a `CrackResult`.

### `bestTripleKey2ForKey1(int key1, int[] ciphertext, BlockTables tables)`

This method tests all `key2` values for one fixed `key1`.

It first computes:

```text
D(k1, ciphertext)
```

once and stores that intermediate result in `firstDecrypt`. This saves work because that first decryption does not change while `key2` changes.

Then for every `key2`:

1. Apply `E(k2)` to each byte of `firstDecrypt`.
2. Apply `D(k1)` to each result.
3. Decode the resulting bytes as CASCII.
4. Score the decoded string.
5. Keep the best result for this `key1`.

This method is the core optimization of the TripleSDES brute force.

### `englishScore(String text)`

This assigns a numeric score to a decoded CASCII candidate.

The score is only a heuristic. Its job is not to prove anything about the key. Its job is to rank the correct English plaintext above random-looking text.

The method rewards:

- frequent English letters
- spaces near a normal ratio
- commas and periods
- common phrases
- words in the `COMMON_WORDS` set

It penalizes:

- too many question marks, colons, or apostrophes
- suspicious single-letter words
- long unknown words
- long words without vowels

The correct plaintexts are far more English-like than the wrong candidates, so they rise to the top.

### `buildBlockTables()`

This builds the SDES lookup tables.

For every key from 0 to 1023 and every byte from 0 to 255, it stores:

```text
encrypt[key][byte] = SDES encryption result
decrypt[key][byte] = SDES decryption result
```

This makes brute forcing much faster because the expensive SDES block logic is done once.

### `encryptBlock(KeySchedule schedule, int plaintextByte)`

This encrypts one 8-bit SDES block.

It:

1. Converts the input byte into 8 bits.
2. Applies the initial permutation.
3. Runs the first Feistel round with `k1`.
4. Switches halves.
5. Runs the second Feistel round with `k2`.
6. Applies the inverse initial permutation.
7. Converts the final 8 bits back to an integer.

### `decryptBlock(KeySchedule schedule, int ciphertextByte)`

This decrypts one 8-bit SDES block.

It is structurally the same as `encryptBlock`, except the round keys are used in reverse:

```text
decrypt uses k2 first, then k1
```

That is the standard Feistel-network property used by SDES.

### `keySchedule(int rawKey)`

This expands one 10-bit raw key into two 8-bit round keys.

It:

1. Converts the raw integer key to 10 bits.
2. Applies `P10`.
3. Left-shifts both 5-bit halves by 1.
4. Applies `P8` to get `k1`.
5. Left-shifts both halves by 2 more.
6. Applies `P8` to get `k2`.

The result is a `KeySchedule` record containing `k1` and `k2`.

### `fk(int[] input, int[] key)`

This is the SDES round function.

It:

1. Takes the right 4 bits of the current block.
2. Expands and permutes those 4 bits to 8 bits with `EP`.
3. XORs the expanded bits with the round key.
4. Sends the left 4 bits through `S0`.
5. Sends the right 4 bits through `S1`.
6. Joins the two S-box outputs.
7. Applies `P4`.

The result is 4 bits. The caller XORs those 4 bits with the left half of the Feistel state.

### `sBox(int[][] box, int[] bits)`

This applies one SDES S-box.

The input is 4 bits:

```text
b0 b1 b2 b3
```

The row is formed from the outside bits:

```text
row = b0 b3
```

The column is formed from the inside bits:

```text
column = b1 b2
```

The selected S-box value is a number from 0 to 3. That number is returned as 2 bits.

### `permute(int[] source, int[] permutation)`

This applies a permutation table.

The permutation arrays use 1-based positions because the SDES specification usually writes them that way. Java arrays are 0-based, so the method reads:

```java
source[permutation[i] - 1]
```

### `shiftBothHalves(int[] bits, int shift)`

This splits the input into left and right halves, circular-shifts each half, and joins them back together.

It is used during key generation because SDES shifts the two 5-bit key halves independently.

### `shift(int[] bits, int shift)`

This performs the circular left shift used by the project implementation.

For a shift of 1, the first bit moves to the end of its half. `Math.floorMod` is used to wrap positions safely.

### `switchHalves(int[] newRight, int[] original)`

This performs the SDES switch operation between rounds.

After the first round, SDES swaps the original right half to the left side and places the newly computed half on the right side.

### `xor(int[] left, int[] right)`

This XORs two equal-length bit arrays.

It is used in both the round function and the Feistel step.

### `leftHalf(int[] bits)` and `rightHalf(int[] bits)`

These return the left or right half of a bit array.

They are convenience methods to keep the SDES block logic readable.

### `slice(int[] bits, int start, int end)`

This copies a range from a bit array.

It is used by the half helpers and by `fk` when splitting the 8-bit S-box input.

### `join(int[] left, int[] right)`

This concatenates two bit arrays.

It is used when rebuilding SDES state after shifts, S-boxes, switches, and final Feistel output.

### `toBits(int value, int width)`

This converts an integer to a bit array of fixed width.

For SDES blocks, `width` is 8. For raw keys, `width` is 10.

The output is normal most-significant-bit first order, which is what the SDES permutation tables expect.

### `fromBits(int[] bits)`

This converts a most-significant-bit-first bit array back into an integer.

It is the inverse of `toBits`.

### `bitsToByte(int[] bits, int start)`

This reads 8 bits from a larger bit array and packs them into one integer byte value.

It is used by part 1 after CASCII encoding has produced one padded bit stream.

### `bitAt(int[] packedBytes, int bitIndex)`

This reads one bit from an array of packed bytes.

It treats each byte as most-significant-bit first. This is needed during CASCII decoding because SDES outputs 8-bit blocks, but CASCII is read in 5-bit character groups across byte boundaries.

### `parseKey(String rawKeyBits)`

This validates and parses a raw 10-bit key string.

It rejects anything that is not exactly ten `0` or `1` characters.

### `readCiphertextBytes(Path path)`

This reads a ciphertext file containing zeros and ones.

It:

1. Resolves the file path.
2. Removes whitespace.
3. Verifies that the number of bits is a multiple of 8.
4. Verifies that every non-whitespace character is `0` or `1`.
5. Packs every 8 bits into one integer byte.

### `defaultAssetPath(String fileName)`

This chooses the default location for `msg1.txt` and `msg2.txt`.

It first checks the Gradle-style repo layout under `assets/`. If that is not present, it falls back to the current directory. This makes the same code work when only the four Java files and two message files are copied into a submission folder.

### `resolvePath(Path path)`

This makes file lookup a little more flexible.

It checks:

1. the path exactly as given
2. the same path from the parent directory

This helps when running from the repo root, from the `app` directory, or from a copied submission folder.

### `appendByteBits(StringBuilder builder, int value)`

This appends one byte as eight `0` or `1` characters.

It is used when printing the part 1 ciphertext.

### `keyToBits(int key)`

This formats an integer key as exactly 10 bits, including leading zeros.

For example:

```text
5 -> 0000000101
```

### `groupBits(String bits)`

This formats a long bit string into 8-bit groups for readability.

It does not change the answer. It only inserts spaces for display.

### `count`, `countAny`, and `countOccurrences`

These are helper methods used by the English scoring function.

- `count` counts one character.
- `countAny` counts any character from a small set.
- `countOccurrences` counts exact phrase matches.

### `hasVowel(String token)`

This checks whether a word-like token contains `A`, `E`, `I`, `O`, `U`, or `Y`.

The score penalizes long tokens with no vowels because random CASCII output often produces strings that do not look like English words.

### `printProcess()`

This prints a short explanation before the program prints the final answers.

It summarizes CASCII, SDES brute force, TripleSDES brute force, and the parallel table-lookup optimization.

### `KeySchedule`

This record stores the two generated SDES round keys:

```java
int[] k1
int[] k2
```

### `BlockTables`

This record stores the precomputed encryption and decryption tables:

```java
byte[][] encrypt
byte[][] decrypt
```

### `CrackResult`

This record stores one brute-force candidate:

```java
int key1
int key2
double score
String plaintext
```

For SDES, `key2` is `-1` because there is only one key. The methods `key1Bits()` and `key2Bits()` format keys as 10-bit strings for printing.

## `Part3.java`

`Part3` is a small convenience wrapper:

```java
CrackTheCode.main(args);
```

It exists so the submission has a class name that directly matches the assignment part. Running `Part3` and running `CrackTheCode` produce the same output.

## `TripleDES.java`

`TripleDES.java` contains the direct TripleSDES formulas using the existing `SDES` class:

```text
E3SDES(k1, k2, p) = Encrypt(k1, Decrypt(k2, Encrypt(k1, p)))
D3SDES(k1, k2, c) = Decrypt(k1, Encrypt(k2, Decrypt(k1, c)))
```

The brute-force code in `CrackTheCode.java` uses the same formula, but it uses precomputed byte tables instead of calling `TripleDES.D3SDES` for every key pair and every byte. That is why it is much faster.

## `SDES.java`

`SDES.java` is the original SDES implementation. It contains the same logical pieces used by `CrackTheCode.java`:

- key generation with `P10`, shifts, and `P8`
- initial and inverse initial permutations
- expansion/permutation
- S-box lookup
- P4 permutation
- Feistel swapping
- encrypt and decrypt methods

`CrackTheCode.java` reimplements the SDES block logic locally with integers so it can build lookup tables cheaply and avoid allocating many `byte[]` arrays during the million-pair TripleSDES search.
