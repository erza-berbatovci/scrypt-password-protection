import hashlib
from typing import ByteString

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