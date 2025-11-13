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