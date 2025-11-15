import hashlib
import struct
import math
from typing import ByteString

# ------------------------- Helper functions -------------------------

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