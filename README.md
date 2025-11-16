# Scrypt Key Derivation Function — Manual Implementation in Python

## 🏛 University of Prishtina  
### Faculty of Computer and Software Engineering  
### Master’s Program in Computer and Software Engineering  
**Professor:** Dr.Sc. Mërgim H. HOTI  

---

### **Group:** 10  
### **Team Members:**  
- Erza Bërbatovci  
- Leotrim Halimi  
- Rinor Ukshini  

---

# Overview

This repository contains a **manual, from-scratch implementation** of the Scrypt Key Derivation Function (KDF) in Python.

The project recreates all internal components of scrypt without using high-level libraries:

- HMAC-SHA256  
- PBKDF2-HMAC-SHA256  
- Salsa20/8 core  
- BlockMix  
- ROMix (memory-hard core)  
- The final Scrypt KDF  

The purpose of this project is **educational**: to clearly show how scrypt works internally and why it is secure against modern parallel brute-force attacks.

---

# What Is Scrypt?

Scrypt is a password hashing and key derivation function designed to be:

- **Memory-hard** (requires large RAM)
- **Slow for attackers, fast for legitimate users**
- Resistant to **GPU, ASIC, and FPGA** cracking
- More secure than classical KDFs such as PBKDF2

Its strength comes from the **ROMix** algorithm, which forces large memory usage and sequential dependencies, making it nearly impossible to optimize using specialized hardware.

---

# Scrypt Implementation

This section explains each part of the code in simple terms.

---

## XOR Function

`xor_bytes(a, b)`  
XORs two byte strings together.  
Used in Salsa20 and ROMix for mixing data.

---

## Manual HMAC-SHA256

`hmac_sha256(key, message)`  

Manually performs HMAC:

1. Pads or hashes the key to 64 bytes  
2. Creates inner (ipad) and outer (opad) masks  
3. Computes: inner_hash = SHA256(ipad + message)
final_hash = SHA256(opad + inner_hash)


Used inside PBKDF2.

---

## PBKDF2-HMAC-SHA256

`pbkdf2_hmac_sha256(password, salt, iterations, dklen)`  

PBKDF2 produces long derived keys by repeatedly hashing the password + salt using HMAC.

For each output block:

1. Compute `U1 = HMAC(password, salt || block_index)`  
2. Hash U repeatedly for `iterations` times  
3. XOR all U-values together to form one block  
4. Repeat until the final key length `dklen` is reached  

Scrypt uses PBKDF2 twice:  
once before ROMix  
once after ROMix  

---

## Salsa20/8 Core

`salsa20_8(B)`  

A reduced-round version of the Salsa20 cipher:

- Operates on 64 bytes  
- Performs 8 rounds of mixing using addition, XOR, and bit-rotation  
- Provides strong diffusion  

Used inside BlockMix.

---

## BlockMix (Uses Salsa20/8)

`blockmix_salsa8(B, r)`  

BlockMix:

- Takes a block of size `128*r` bytes  
- Splits it into 64-byte chunks  
- Mixes each chunk with Salsa20/8  
- Rearranges even and odd results  

BlockMix increases diffusion and prepares data for ROMix.

---

## Integerify

`integerify(B, r)`  

Extracts a 64-bit integer from the last block.  
This integer is used to select which memory block ROMix should access next.

---

## ROMix — Scrypt's Memory-Hard Engine

`romix(B, N, r)`  

ROMix is the **core** of scrypt’s security.

### Step 1 — Fill Memory
for i in 0…N−1:
    V[i] = X
    X = BlockMix(X)

This stores N blocks in memory, forcing the algorithm to use **N × 128 × r bytes of RAM**.

### Step 2 — Random Memory Access

for i in 0…N−1:
j = Integerify(X) mod N
X = X XOR V[j]
X = BlockMix(X)


This step:

- Forces sequential operations  
- Makes memory access unpredictable  
- Prevents GPU/ASIC parallelization  

The result of ROMix is the final mixed block `X`.

---

## Full Scrypt KDF

`scrypt_kdf(password, salt, N, r, p, dklen)`  

This ties all components together:

1. PBKDF2 expands the password → produces `p` large blocks  
2. Each block goes through ROMix  
3. All ROMix outputs are concatenated  
4. PBKDF2 compresses everything → produces the final derived key  

### Parameters:
- **N** — CPU/memory cost  
- **r** — block size  
- **p** — parallelization  
- **dklen** — length of final key  

---

# Example Usage

```python
password = b'password'
salt = b'somesalt'
N = 2**14
r = 1
p = 1
dklen = 64

dk = scrypt_kdf(password, salt, N, r, p, dklen)
print("Derived key:", dk.hex())


