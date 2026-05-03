# SDES Part 3 Submission

This project can be submitted and run with only these four Java files:

- `CrackTheCode.java`
- `Part3.java`
- `SDES.java`
- `TripleDES.java`

The code uses `package org.example;`, so keep the package line in each file and compile with `javac -d out`.

## Requirements

- JDK 17 or newer
- `msg1.txt` and `msg2.txt` available when running the cracker

Check Java:

```sh
javac -version
java -version
```

## Compile And Run With Only javac

Put the four `.java` files in one folder. Put `msg1.txt` and `msg2.txt` in that same folder, or pass their paths as command-line arguments.

```sh
mkdir -p out
javac -d out *.java
java -cp out org.example.Part3
```

`Part3` is only a wrapper around `CrackTheCode`, so this equivalent command also works:

```sh
java -cp out org.example.CrackTheCode
```

If the message files are somewhere else, pass both paths explicitly:

```sh
java -cp out org.example.CrackTheCode path/to/msg1.txt path/to/msg2.txt
```

The program looks for default message files in this order:

1. `assets/msg1.txt` and `assets/msg2.txt`
2. `../assets/msg1.txt` and `../assets/msg2.txt`
3. `msg1.txt` and `msg2.txt`
4. `../msg1.txt` and `../msg2.txt`

## Expected Output

The program prints a short explanation of the process, then prints:

- the SDES encoding of CASCII `CRYPTOGRAPHY` with key `0111001101`
- the SDES key and plaintext for `msg1.txt`
- the TripleSDES key pair and plaintext for `msg2.txt`

Expected answers:

```text
1) SDES(CASCII("CRYPTOGRAPHY"), key 0111001101)
0110000111001010101101101111010011000101011101101111110001110111
01100001 11001010 10110110 11110100 11000101 01110110 11111100 01110111

2) msg1.txt
Raw key: 1011110100
Plaintext: WHOEVER THINKS HIS PROBLEM CAN BE SOLVED USING CRYPTOGRAPHY, DOESN'T UNDERSTAND HIS PROBLEM AND DOESN'T UNDERSTAND CRYPTOGRAPHY.  ATTRIBUTED BY ROGER NEEDHAM AND BUTLER LAMPSON TO EACH OTHER

3) msg2.txt
Raw keys: 1110000101, 0101100011
Plaintext: THERE ARE NO SECRETS BETTER KEPT THAN THE SECRETS THAT EVERYBODY GUESSES.
```

## Notes

The full brute-force explanation is in `BRUTEFORCE_EXPLANATION.md`.
