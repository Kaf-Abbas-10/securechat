#!/usr/bin/env python3
"""
AES-128 (ECB mode) + PKCS#7 padding helpers.

Usage:
    from app.crypto import aes

    key = b"0123456789abcdef"  # 16 bytes
    plaintext = b"Hello secure world!"
    ciphertext = aes.encrypt(plaintext, key)
    recovered = aes.decrypt(ciphertext, key)
"""

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


BLOCK_SIZE = 16  # AES block size (128 bits)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-128 (ECB mode) with PKCS#7 padding.
    Args:
        plaintext: bytes to encrypt
        key: 16-byte AES key
    Returns:
        ciphertext (bytes)
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes long")

    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    return ciphertext


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-128 (ECB) ciphertext and remove PKCS#7 padding.
    Args:
        ciphertext: bytes to decrypt
        key: 16-byte AES key
    Returns:
        plaintext (bytes)
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes long")

    cipher = AES.new(key, AES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded, BLOCK_SIZE)
    except ValueError:
        raise ValueError("Decryption failed: invalid padding or key")
    return plaintext


# --- CLI Testing Helper ---
if __name__ == "__main__":
    key = b"thisis16bytekey!"  # 16 bytes
    message = b"Confidential chat message"
    print("[+] AES-128 ECB test")
    print(f"Plaintext : {message}")

    ct = encrypt(message, key)
    print(f"Ciphertext: {ct.hex()}")

    pt = decrypt(ct, key)
    print(f"Decrypted : {pt}")
