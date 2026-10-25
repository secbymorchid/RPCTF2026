# Operation Failed

<p align="center">
  <img src="https://img.shields.io/badge/Category-Cryptography-yellow?style=for-the-badge&logo=auth0" alt="Category">
  <img src="https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge" alt="Difficulty">
  <img src="https://img.shields.io/badge/Points-350-blue?style=for-the-badge" alt="Points">
  <img src="https://img.shields.io/badge/Cipher-Repeating%20XOR%20|%20Base64%20|%20ROT13-lightgrey?style=for-the-badge&logo=gnupg" alt="Cipher">
</p>

---

## Executive Summary

`Operation Failed` is a multi-tier cryptographic challenge involving an intercepted military communication encrypted with a **repeating-key XOR cipher**. The briefing reveals that all communications include a known header (`OPERATION_PLAN:`), but an unknown preamble precedes it. By implementing a **known-plaintext slide attack**, we test each possible byte offset of the ciphertext against the known header. At offset 9, the candidate key emerges as ASCII text `PHOENIXRISES123`. Decrypting the complete ciphertext reveals mission instructions and an encoded authorization token. Decoding this token via **Base64** followed by a **ROT13 substitution** recovers the final flag: `RPCTF{strike_at_first_light}`.

---

## Fundamental Concepts for Beginners

### 1. The Mathematics of XOR ($\oplus$)
Exclusive OR (XOR) is the backbone of classical and modern symmetric ciphers. It possesses three crucial mathematical properties:
1. **Self-Inverting:** $A \oplus B = C \iff C \oplus B = A \iff C \oplus A = B$
2. **Identity:** $A \oplus 0 = A$
3. **Nilpotence:** $A \oplus A = 0$

In a **repeating-key XOR cipher**, a secret key $K$ of length $L$ is tiled repeatedly across plaintext $P$ to produce ciphertext $C$:
$$C[i] = P[i] \oplus K[i \pmod L]$$

### 2. The Known-Plaintext Attack (KPA)
Because XOR is self-inverting, if an attacker knows (or accurately guesses) even a small fragment of the plaintext $P$, they can immediately calculate the exact key bytes used for that region:
$$K[i \pmod L] = C[i] \oplus P[i]$$

### 3. The Slide Attack Window
If we know that `OPERATION_PLAN:` appears in the message, but do not know its exact position (due to variable headers like `ID:1234. `), we can "slide" the known plaintext along the ciphertext, byte by byte, testing each candidate key for readable alphanumeric ASCII characters.

```
Ciphertext:  [ 11 16 73 64 77 6b 04 1c 13 1f 18 0a 17 0f 1d 11 1d ... ]
Known Plain:                      [ O  P  E  R  A  T  I  O  N  _  P  L  A  N  : ]
                                    |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
Candidate:                        [ P  H  O  E  N  I  X  R  I  S  E  S  1  2  3 ]
                                    \___________________________________________/
                                             VALID ALPHANUMERIC KEY!
```

---

## Step 1: Intelligence Briefing & Intercepted Ciphertext

The challenge intelligence report states:
> *"During an ongoing conflict, our intelligence unit intercepted an encrypted enemy transmission believed to contain details of their next strike.*  
> *Analysts discovered that all official communications include the standard header:*  
> `OPERATION_PLAN:`  
> *However, this transmission appears to contain some additional data before the actual message.*  
> *The enemy used a repeating-key XOR cipher for encryption.*  
> *Recover the original message and uncover the attack details."*

### Intercepted Hexadecimal Stream:
```text
11167364776b041c131f180a170f1d111d070c151f707c0970091b110f0a130d08071a17
70657d7e681b041c0e1d067373071262776c11041f0d0f6778131c070d0c727d7715726f
1c19312c307a1d751a79605c0a100529071a19351b060b0263037d67122221222d363a30
0b77665f6a001e7a1512142700612561211b675c550175726b
```
Total length: **133 bytes**.

---

## Step 2: The Known-Plaintext Sliding Window Attack

We test the known header against the ciphertext at each byte offset `b"OPERATION_PLAN:"` across every possible byte offset ($0 \le \text{offset} \le 133 - 15$):

```python
ciphertext = bytes.fromhex(
    "11167364776b041c131f180a170f1d111d070c151f707c0970091b110f0a130d08071a17"
    "70657d7e681b041c0e1d067373071262776c11041f0d0f6778131c070d0c727d7715726f"
    "1c19312c307a1d751a79605c0a100529071a19351b060b0263037d67122221222d363a30"
    "0b77665f6a001e7a1512142700612561211b675c550175726b"
)
needle = b"OPERATION_PLAN:"

print("[*] Testing offsets for repeating key candidates...")
for offset in range(len(ciphertext) - len(needle)):
    chunk = ciphertext[offset : offset + len(needle)]
    candidate_key = bytes([c ^ p for c, p in zip(chunk, needle)])
    
    # Filter candidates that consist entirely of printable ASCII
    if candidate_key.isalnum():
        print(f"[+] Match found at offset {offset:2d}: Key = {candidate_key.decode()}")
```

### Execution Output:
```text
[*] Testing offsets for repeating key candidates...
[+] Match found at offset  9: Key = PHOENIXRISES123
```

At **offset 9**, the candidate key evaluates cleanly to `PHOENIXRISES123` (15 characters)!

---

## Step 3: Aligning the Key & Full XOR Decryption

Since the key `PHOENIXRISES123` was derived starting at byte 9, we must rotate/phase the key so that byte 0 of the ciphertext is decrypted with the corresponding key byte:
$$\text{Shift} = (15 - (9 \pmod{15})) \pmod{15} = 6$$

```python
key = b"PHOENIXRISES123"
offset = 9
shift = (len(key) - (offset % len(key))) % len(key)
aligned_key = key[shift:] + key[:shift]

decrypted = bytes([c ^ aligned_key[i % len(aligned_key)] for i, c in enumerate(ciphertext)])
print(decrypted.decode("latin1"))
```

### Decrypted Plaintext:
```text
ID:7285. OPERATION_PLAN: ATTACK_AT_DAWN. TARGET: BASE_ALPHA. AUTH_CODE: YWxtb3N0IHRoZXJlISAgRUNQR1N7ZmdldnhyX25nX3N2ZWZnX3l2dHVnfQ==.
```

### Breakdown of the Plaintext:
- **Preamble (9 bytes):** `ID:7285. ` (explains the 9-byte offset!)
- **Operational Directive:** `OPERATION_PLAN: ATTACK_AT_DAWN. TARGET: BASE_ALPHA.`
- **Authorization Token:** `AUTH_CODE: YWxtb3N0IHRoZXJlISAgRUNQR1N7ZmdldnhyX25nX3N2ZWZnX3l2dHVnfQ==.`

---

## Step 4: Multi-Layer Decoding (Base64 & ROT13)

### 1. Base64 Decoding
The auth code ends with `==`, indicative of standard Base64 padding:

```bash
$ echo "YWxtb3N0IHRoZXJlISAgRUNQR1N7ZmdldnhyX25nX3N2ZWZnX3l2dHVnfQ==" | base64 -d
almost there!  ECPGS{fgevxr_ng_svefg_yvtug}
```

### 2. ROT13 Decryption
Notice the flag header `ECPGS{...}`:
- `E` (+13) $\rightarrow$ `R`
- `C` (+13) $\rightarrow$ `P`
- `P` (+13) $\rightarrow$ `C`
- `G` (+13) $\rightarrow$ `T`
- `S` (+13) $\rightarrow$ `F`

Applying the ROT13 Caesar cipher shift ($c \mapsto (c + 13) \pmod{26}$):

```bash
$ echo "ECPGS{fgevxr_ng_svefg_yvtug}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
RPCTF{strike_at_first_light}
```

---

## Output & Final Flag

**Captured Flag:**
```
RPCTF{strike_at_first_light}
```

``

---

## Cryptographic Security Lessons

1. **Repeating-Key XOR is Fundamentally Insecure:**
   Repeating a key transforms a stream cipher into a monoalphabetic or polyalphabetic substitution cipher, vulnerable to frequency analysis, Kasiski examination, and known-plaintext attacks.
2. **One-Time Pad (OTP) Requirements:**
   A one-time pad is mathematically unbreakable *only* if the key is:
   - Truly random.
   - At least as long as the plaintext.
   - **Never reused**.
3. **Defense: Use Authenticated Encryption:**
   Modern protocols require Authenticated Encryption with Associated Data (AEAD), such as AES-256-GCM or ChaCha20-Poly1305, providing both confidentiality and cryptographic integrity.
