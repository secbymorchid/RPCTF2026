# bytewarden

<p align="center">
  <img src="https://img.shields.io/badge/Category-Reverse%20Engineering-purple?style=for-the-badge&logo=ida" alt="Category">
  <img src="https://img.shields.io/badge/Difficulty-Hard-red?style=for-the-badge" alt="Difficulty">
  <img src="https://img.shields.io/badge/Points-500-blue?style=for-the-badge" alt="Points">
  <img src="https://img.shields.io/badge/Binary-x86--64%20Static%20ELF-lightgrey?style=for-the-badge&logo=linux" alt="Format">
</p>

---

## Executive Summary

`bytewarden` is a statically linked, stripped 64-bit ELF binary implementing a custom **Virtual Machine (VM) crackme**. Before initializing the virtual CPU, the binary computes an **FNV-1a 64-bit integrity hash** over a custom ELF section named `warden`. This hash is not checked against a static value; instead, it seeds an `xorshift64*` pseudorandom number generator (PRNG) that constructs a dynamic S-box and round keys. Any attempt to modify the binary or insert software breakpoints (`0xCC`) alters the hash, breaking the key schedule. The VM decrypts its own bytecode and subjects the user's 32-byte input to a **16-round block cipher** consisting of SubBytes, Permutation, ARX mixing, and Round-Key XOR. Because every transformation in the pipeline is strictly bijective (invertible), we bypass symbolic execution and solve the challenge via an exact analytical backward inversion.

---

## Fundamental Concepts for Beginners

### 1. What is a Custom VM Crackme?
In standard reverse engineering, you analyze CPU instructions like `mov`, `add`, or `jmp` native to x86 or ARM. In a **VM-based crackme**, the author builds an emulated processor inside the binary:
1. **Virtual CPU Loop (Dispatcher):** Reads custom byte sequences (bytecode) one by one.
2. **Instruction Set Architecture (ISA):** Custom opcodes mapped to handler routines via a switch statement or jump table.
3. **Virtual State:** Dedicated registers, stack, and memory buffers simulating an execution environment.

This technique is widely used in commercial software protection (e.g., VMProtect, Denuvo) and malware to defeat static analysis and decompilers.

```
+--------------------------------------------------------------------------+
|                            Native Application                            |
|                                                                          |
|  [ User Input ] ---> [ FNV-1a Hash ] ---> [ xorshift64* PRNG ]          |
|                                                    |                     |
|                                          +---------+---------+           |
|                                          v                   v           |
|                                    [ 256B S-Box ]     [ 32B Key ]        |
|                                          |                   |           |
|   +--------------------------------------v-------------------v-------+   |
|   |                       Custom Virtual Machine                     |   |
|   |                                                                  |   |
|   |   [Encrypted Bytecode] ---> [Rolling XOR] ---> [158 VM Opcodes]  |   |
|   |                                                      |           |   |
|   |         +--------------------------------------------+           |   |
|   |         v                                                        |   |
|   |   [ 16-Round Block Cipher: SubBytes -> Perm -> ARX -> KeyXOR ]   |   |
|   +--------------------------------------|---------------------------+   |
|                                          v                               |
|                  [ Compare with 32 Target Bytes ]                        |
+--------------------------------------------------------------------------+
```

### 2. The "Hash-as-Seed" Anti-Tampering Pattern
Traditional anti-tampering checks compare a checksum against an expected constant:
```c
if (calculate_hash() != EXPECTED_HASH) exit(1);
```
An analyst can easily bypass this by patching the `jne` jump instruction.

In `bytewarden`, the author uses the checksum directly as the PRNG seed:
```c
uint64_t seed = fnv1a_hash(code_section);
prng_init(seed); // No 'if' check to patch!
```
If you alter a single byte in the binary or place a software breakpoint (`\xCC` / `int3`), the seed changes silently, corrupting the S-box and round keys, guaranteeing that the flag verification will fail downstream.

---

## Step 1: Binary Reconnaissance & Section Analysis

We inspect the binary using `file` and `readelf`:

```bash
$ file bytewarden
bytewarden: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped

$ readelf -S -W bytewarden | grep -E "warden|\.data"
  [ 5] warden            PROGBITS        0000000000477a00 077a00 00048f 00  AX  0   0 16
  [21] .data             PROGBITS        00000000004a40c0 0a40c0 001ba0 00  WA  0   0 32
```

### Observations:
- **Stripped & Static:** All symbol names have been removed. Standard glibc functions are compiled directly into the binary.
- **Custom Section `warden`:** A non-standard executable section located at `0x477a00` of size `0x48f` (1,167 bytes). This houses the VM interpreter.
- **Data Section `.data`:** Holds encrypted bytecode and target comparison buffers starting at `0x4a40c0`.

---

## Step 2: Dissecting the Anti-Tamper & Initialization Routine

Tracing the entrypoint into `main` (`0x401680`) reveals four sequential preparation stages:

### 1. FNV-1a 64-bit Hash of the `warden` Section
The binary computes a 64-bit hash over the memory range `0x477a00` to `0x477e8e`:
$$\text{hash} \leftarrow 0xcbf29ce484222325$$
$$\text{For each byte } b: \quad \text{hash} \leftarrow (\text{hash} \oplus b) \times 0x100000001b3 \pmod{2^{64}}$$

On an unmodified binary, this computation yields:
$$\text{hash} = \text{0xf0c8375c69bc69f6}$$

### 2. PRNG Setup (`xorshift64*`)
The hash `h` is loaded as the initial state of a 64-bit `xorshift64*` algorithm:
```python
def xorshift64star(state):
    state ^= (state >> 12) & 0xFFFFFFFFFFFFFFFF
    state ^= (state << 25) & 0xFFFFFFFFFFFFFFFF
    state ^= (state >> 27) & 0xFFFFFFFFFFFFFFFF
    return (state * 0x2545f4914f6cdd1d) & 0xFFFFFFFFFFFFFFFF
```

Using this PRNG:
- A **256-byte S-box** is generated via a backward Fisher-Yates shuffle starting from array `[0, 1, 2, ..., 255]`.
- A **32-byte master key** is generated by sampling the high 8 bits of 32 consecutive PRNG steps.

### 3. Decrypting the Bytecode
At `.data:0x4a4100`, 474 bytes of encrypted bytecode are stored. They are decrypted using an 8-byte static key (`.data:0x4a42e0`) combined with an index-dependent counter:
```python
enc_bytecode = data[0x4a4100 : 0x4a4100 + 474]
key8 = data[0x4a42e0 : 0x4a42e0 + 8]
bytecode = bytes(((enc_bytecode[i] ^ ((0x1f * i) & 0xff)) ^ key8[i & 7]) & 0xff for i in range(474))
```
Since each instruction is 3 bytes long, this yields exactly $474 / 3 = \mathbf{158}$ instructions.

---

## Step 3: The Custom VM & 16-Round Block Cipher

Each virtual instruction follows a fixed 3-byte format:
```
[ Opcode (1 byte) ] [ Operand A (1 byte) ] [ Operand B (1 byte) ]
```

The VM executes an instruction loop with a jump table located at `0x478010`. Disassembling the 158 instructions reveals that the program executes a cryptographic SPN (Substitution-Permutation Network) block cipher:

### The Cryptographic Pipeline:
1. **Pre-Whitening:** User input (32 bytes) is XORed with the round key at round index `0x10`.
2. **16 Encryption Rounds (Round $r = 0 \dots 15$):**
   - **SubBytes (S-Box):** Each byte $x$ is replaced with $\text{SBox}[x]$.
   - **Permutation (`PERM`):** Bytes are transposed according to:
     $$\text{PERM}[i] = (i \ \& \ \text{0x18}) \ | \ ((i + (i \gg 3)) \ \& \ 7)$$
   - **ARX Layer (Column Mixing):** 8 columns of 4 bytes $[a, b, c, d]$ undergo Addition-Rotation-XOR mixing:
     $$\begin{aligned}
     a' &= a + d \\
     b' &= b \oplus \text{ROL}_3(a') \\
     c' &= c + b' \\
     d' &= d \oplus \text{ROL}_5(c') \\
     a'' &= a' + d'
     \end{aligned}$$
   - **Round Key XOR:** Mixed state is XORed with a round-derived key.
3. **Final Comparison:** The output 32 bytes are compared against hardcoded constants at `.data:0x4a40e0`.

---

## Step 4: Analytical Reversal & Inversion Solution

Because every operation is mathematically reversible and bijective, we don't need SAT solvers or z3. We can invert the entire cipher backward from the target constants!

### Inverting the Components:
1. **Inverse Round Key XOR:** Self-inverse (XOR with the exact same round key).
2. **Inverse ARX Layer:** We reverse the sequence of arithmetic and rotations:
   $$\begin{aligned}
   a' &= (a'' - d') \pmod{256} \\
   d &= d' \oplus \text{ROL}_5(c') \\
   c &= (c' - b') \pmod{256} \\
   b &= b' \oplus \text{ROL}_3(a') \\
   a &= (a' - d) \pmod{256}
   \end{aligned}$$
3. **Inverse Permutation:** Precompute $\text{inv\_perm}[\text{PERM}[i]] = i$.
4. **Inverse S-Box:** Precompute $\text{inv\_sbox}[\text{SBox}[i]] = i$.

---

## Analytical Reversal Algorithm

```python
#!/usr/bin/env python3
"""
RPCTF 2026 - bytewarden Solver
Author: secbymorchid
Description: Exact analytical backward reversal of custom 16-round VM cipher.
"""

import sys

MASK64 = (1 << 64) - 1
MUL64  = 0x2545f4914f6cdd1d

def solve(binary_path="bytewarden"):
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] Error: '{binary_path}' not found.")
        sys.exit(1)

    read_mem = lambda vaddr, size: data[vaddr - 0x400000 : vaddr - 0x400000 + size]

    print("[*] Stage 1: Calculating FNV-1a 64-bit integrity hash...")
    h = 0xcbf29ce484222325
    warden_bytes = read_mem(0x477a00, 0x48f)
    for b in warden_bytes:
        h ^= b
        h = (h * 0x100000001b3) & MASK64
    
    print(f"[+] Computed Seed Hash: 0x{h:016x}")

    # PRNG generator
    prng_state = h or 1
    def prng_step():
        nonlocal prng_state
        prng_state ^= (prng_state >> 12) & MASK64
        prng_state ^= (prng_state << 25) & MASK64
        prng_state ^= (prng_state >> 27) & MASK64
        return (prng_state * MUL64) & MASK64

    print("[*] Stage 2: Reconstructing dynamic S-Box and Master Key...")
    sbox = list(range(256))
    for i in range(256, 1, -1):
        j = prng_step() % i
        sbox[i - 1], sbox[j] = sbox[j], sbox[i - 1]

    # Invert S-Box
    inv_sbox = [0] * 256
    for idx, val in enumerate(sbox):
        inv_sbox[val] = idx

    master_key = bytes(prng_step() >> 56 for _ in range(32))
    target_bytes = list(read_mem(0x4a40e0, 32))

    rol = lambda v, n: ((v << n) | (v >> (8 - n))) & 0xff

    def key_xor(state, r):
        r3 = ((r << 5) ^ (r << 1) ^ r ^ 0x5c) & 0xff
        res = state[:]
        for i in range(32):
            res[i] = state[i] ^ master_key[(i + r) & 0x1f] ^ r3
            r3 = (r3 + 0x35) & 0xff
        return res

    # Inverse Permutation
    perm = [(i & 0x18) | ((i + (i >> 3)) & 7) for i in range(32)]
    def inverse_perm(state):
        res = [0] * 32
        for i in range(32):
            res[perm[i]] = state[i]
        return res

    # Inverse ARX column mixing
    def inverse_arx(state):
        state = state[:]
        for c in range(8):
            a2, b1, c1, d1 = state[c], state[c + 8], state[c + 16], state[c + 24]
            a1 = (a2 - d1) & 0xff
            dd = d1 ^ rol(c1, 5)
            cc = (c1 - b1) & 0xff
            bb = b1 ^ rol(a1, 3)
            aa = (a1 - dd) & 0xff
            state[c], state[c + 8], state[c + 16], state[c + 24] = aa, bb, cc, dd
        return state

    print("[*] Stage 3: Inverting 16 encryption rounds backwards from target...")
    curr = target_bytes
    for r in range(15, -1, -1):
        curr = [inv_sbox[v] for v in inverse_perm(inverse_arx(key_xor(curr, r)))]

    print("[*] Stage 4: Inverting initial pre-whitening layer (r = 0x10)...")
    curr = key_xor(curr, 0x10)

    flag = bytes(curr).rstrip(b'\x00').decode('latin1')
    print(f"\n[+] SUCCESS! Captured Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
```

---

## Output & Flag Capture

```bash
$ python3 solve_bytewarden.py
[*] Stage 1: Calculating FNV-1a 64-bit integrity hash...
[+] Computed Seed Hash: 0xf0c8375c69bc69f6
[*] Stage 2: Reconstructing dynamic S-Box and Master Key...
[*] Stage 3: Inverting 16 encryption rounds backwards from target...
[*] Stage 4: Inverting initial pre-whitening layer (r = 0x10)...

[+] SUCCESS! Captured Flag: RPCTF{fr0m_h4f47_4l_34rch}
```

**Captured Flag:**
```
RPCTF{fr0m_h4f47_4l_34rch}
```

---

## Key Takeaways & Security Engineering Lessons

1. **Hash-as-Seed vs. Hardcoded Checks:**
   Embedding integrity hashes directly into the algorithmic pipeline (e.g., seeding cryptographic keys) is dramatically more robust than simple comparison branches (`cmp / jne`), which can be patched trivially in memory.
2. **Bijectivity in Crackme Design:**
   If every round in a custom cipher is strictly invertible without a trapdoor (no one-way hashes or lossy modular reductions), the system can be cracked analytically backwards from the final output without searching or brute forcing.
