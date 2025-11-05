#!/usr/bin/env python3
"""
Helper utilities for encoding, hashing, and timestamps.

Functions:
    now_ms()       -> current UTC time in milliseconds
    b64e(bytes)    -> Base64 encode to str
    b64d(str)      -> Base64 decode to bytes
    sha256_hex()   -> SHA-256 hash as hex string
"""

import base64
import hashlib
import time


def now_ms() -> int:
    """Return current UTC time in milliseconds."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Base64-encode bytes -> UTF-8 string."""
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    """Base64-decode string -> bytes."""
    return base64.b64decode(s.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 digest of data and return as hex string."""
    return hashlib.sha256(data).hexdigest()


# --- CLI Testing Helper ---
if __name__ == "__main__":
    print("[+] Testing utils.py helpers")

    b = b"Bitshift Secure Chat"
    print("now_ms():", now_ms())
    print("b64e():", b64e(b))
    print("b64d():", b64d(b64e(b)))
    print("sha256_hex():", sha256_hex(b))
