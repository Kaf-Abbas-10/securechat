#!/usr/bin/env python3
"""
Classic Diffie–Hellman key exchange helpers
+ AES key derivation: Trunc16(SHA256(Ks)).

This module provides:
    - generate_parameters()
    - generate_private_key()
    - compute_public_key()
    - compute_shared_secret()
    - derive_aes_key(shared_secret)

Usage (client/server):
    # shared parameters
    p, g = dh.generate_parameters()

    # each party generates private/public pair
    a = dh.generate_private_key()
    A = dh.compute_public_key(g, a, p)

    # exchange A/B, compute shared secret
    Ks = dh.compute_shared_secret(B, a, p)
    K = dh.derive_aes_key(Ks)
"""

import secrets
import hashlib

# RFC 3526 2048-bit MODP Group prime (safe prime)
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DEFAULT_G = 2


def generate_parameters():
    """Return shared DH parameters (p, g)."""
    return DEFAULT_P, DEFAULT_G


def generate_private_key(p: int = DEFAULT_P) -> int:
    """Generate a random private exponent in [2, p-2]."""
    return secrets.randbelow(p - 2) + 2


def compute_public_key(g: int, private_key: int, p: int) -> int:
    """Compute public key A = g^a mod p."""
    return pow(g, private_key, p)


def compute_shared_secret(peer_pub: int, private_key: int, p: int) -> int:
    """Compute shared secret Ks = peer_pub^private_key mod p."""
    return pow(peer_pub, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive 16-byte AES key:
        K = Trunc16(SHA256(big-endian(shared_secret)))
    """
    shared_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    hash_bytes = hashlib.sha256(shared_bytes).digest()
    return hash_bytes[:16]


# --- CLI Testing Helper ---
if __name__ == "__main__":
    p, g = generate_parameters()
    print("[+] Using default 2048-bit MODP group")

    # Alice's side
    a = generate_private_key(p)
    A = compute_public_key(g, a, p)

    # Bob's side
    b = generate_private_key(p)
    B = compute_public_key(g, b, p)

    # Exchange A, B and derive secrets
    Ks1 = compute_shared_secret(B, a, p)
    Ks2 = compute_shared_secret(A, b, p)

    K1 = derive_aes_key(Ks1)
    K2 = derive_aes_key(Ks2)

    print(f"Alice AES key: {K1.hex()}")
    print(f"Bob   AES key: {K2.hex()}")
    print(f"Keys match?   {K1 == K2}")
