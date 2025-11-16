import hashlib
import struct
import math
from typing import ByteString


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def hmac_sha256(key: ByteString, message: ByteString) -> bytes:
    """Manual HMAC-SHA256 implementation."""
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))

    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5c) for x in key)

    inner = hashlib.sha256(ipad + message).digest()
    return hashlib.sha256(opad + inner).digest()

def pbkdf2_hmac_sha256(password: ByteString, salt: ByteString, iterations: int, dklen: int) -> bytes:

    hlen = 32
    l = math.ceil(dklen / hlen)
    r = dklen - (l - 1) * hlen

    def F(block_index: int) -> bytes:
        int_block = struct.pack('>I', block_index)
        U = hmac_sha256(password, salt + int_block)
        T = bytearray(U)
        for _ in range(1, iterations):
            U = hmac_sha256(password, U)
            for i in range(hlen):
                T[i] ^= U[i]
        return bytes(T)

    DK = b''.join(F(i + 1) for i in range(l))
    return DK[:dklen]

def R(a: int, b: int) -> int:
    return ((a << b) & 0xffffffff) | (a >> (32 - b))


def quarterround(y0, y1, y2, y3):
    z1 = y1 ^ R((y0 + y3) & 0xffffffff, 7)
    z2 = y2 ^ R((z1 + y0) & 0xffffffff, 9)
    z3 = y3 ^ R((z2 + z1) & 0xffffffff, 13)
    z0 = y0 ^ R((z3 + z2) & 0xffffffff, 18)
    return z0, z1, z2, z3


def rowround(y):
    z = list(y)
    z[0], z[1], z[2], z[3] = quarterround(y[0], y[1], y[2], y[3])
    z[5], z[6], z[7], z[4] = quarterround(y[5], y[6], y[7], y[4])
    z[10], z[11], z[8], z[9] = quarterround(y[10], y[11], y[8], y[9])
    z[15], z[12], z[13], z[14] = quarterround(y[15], y[12], y[13], y[14])
    return z

def columnround(x):
    y = list(x)
    y[0], y[4], y[8], y[12] = quarterround(x[0], x[4], x[8], x[12])
    y[5], y[9], y[13], y[1] = quarterround(x[5], x[9], x[13], x[1])
    y[10], y[14], y[2], y[6] = quarterround(x[10], x[14], x[2], x[6])
    y[15], y[3], y[7], y[11] = quarterround(x[15], x[3], x[7], x[11])
    return y


def doubleround(x):
    return rowround(columnround(x))


def salsa20_8(B: bytes) -> bytes:
    """Salsa20/8 core. B is 64 bytes, returns 64-byte transformed block."""
    if len(B) != 64:
        raise ValueError('Salsa20/8 requires 64-byte input')
    x = list(struct.unpack('<16I', B))
    original = list(x)
    for _ in range(4):
        x = doubleround(x)
    result = [(x[i] + original[i]) & 0xffffffff for i in range(16)]
    return struct.pack('<16I', *result)


def blockmix_salsa8(B: bytes, r: int) -> bytes:
    """BlockMix using Salsa20/8. B length = 128 * r bytes."""
    if len(B) != 128 * r:
        raise ValueError('Block size mismatch')
    X = B[-64:]
    out = bytearray(len(B))
    blocks = [B[i*64:(i+1)*64] for i in range(2 * r)]
    for i in range(2 * r):
        X = xor_bytes(X, blocks[i])
        X = salsa20_8(X)
        dest_index = i // 2 + (0 if (i % 2 == 0) else r)
        out[dest_index*64:(dest_index+1)*64] = X
    return bytes(out)


def integerify(B: bytes, r: int) -> int:
    last_block = B[(2*r - 1) * 64 : (2*r) * 64]
    return struct.unpack('<Q', last_block[:8])[0]


def romix(B: bytes, N: int, r: int) -> bytes:
    """ROMix per scrypt spec. B is 128*r bytes. Returns transformed B."""
    if N & (N - 1) != 0:
        raise ValueError('N must be a power of 2')
    V = [b''] * N
    X = B
    for i in range(N):
        V[i] = X
        X = blockmix_salsa8(X, r)
    for i in range(N):
        j = integerify(X, r) & (N - 1)
        X = xor_bytes(X, V[j])
        X = blockmix_salsa8(X, r)
    return X


def scrypt_kdf(password: ByteString, salt: ByteString, N: int, r: int, p: int, dklen: int) -> bytes:
    """High-level scrypt KDF using manual PBKDF2 and ROMix.
    Returns dklen bytes.
    """
    if N <= 1 or (N & (N - 1)) != 0:
        raise ValueError('N must be > 1 and a power of 2')
    if r * p >= (1 << 30):
        raise ValueError('Parameters r and p too large')

    B = pbkdf2_hmac_sha256(password, salt, iterations=1, dklen=p * 128 * r)

    B_blocks = [B[i * 128 * r:(i + 1) * 128 * r] for i in range(p)]
    for i in range(p):
        B_blocks[i] = romix(B_blocks[i], N, r)

    B_final = b''.join(B_blocks)
    return pbkdf2_hmac_sha256(password, B_final, iterations=1, dklen=dklen)


if __name__ == '__main__':
    password = b'password'
    salt = b'somesalt'
    N = 2**14
    r = 1
    p = 1
    dklen = 64

    print('Deriving key (this may be slow for larger N)...')
    dk = scrypt_kdf(password, salt, N, r, p, dklen)
    print('Derived key (hex):', dk.hex())