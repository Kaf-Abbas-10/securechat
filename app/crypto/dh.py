#!/usr/bin/env python3
"""
Classic Diffie–Hellman helpers + Trunc16(SHA256(Ks)) derivation.
"""

import secrets
import hashlib


class DHKeyPair:
    """
    Classic Diffie–Hellman key exchange helper.

    Attributes:
        g (int): generator
        p (int): large prime modulus
        private (int): private exponent (random)
        public (int): public value (g^a mod p)
    """

    def __init__(self, g: int = None, p: int = None):
        # Default to a safe 2048-bit MODP group if not provided
        if g is None:
            g = 2
        if p is None:
            # RFC 3526 2048-bit MODP group prime
            p = int(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                "E485B576625E7EC6F44C42E9A63A36210000000000090563",
                16,
            )

        self.g = g
        self.p = p
        self.private = secrets.randbits(256)
        self.public = pow(self.g, self.private, self.p)

    def compute_shared_key(self, other_public: int) -> bytes:
        """
        Compute shared secret Ks = (other_public ^ private) mod p,
        then derive AES-128 key as Trunc16(SHA256(Ks_bytes)).
        """
        Ks = pow(other_public, self.private, self.p)
        Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, "big")
        sha = hashlib.sha256(Ks_bytes).digest()
        return sha[:16]  # 16 bytes for AES-128


# --- CLI Testing Helper ---
if __name__ == "__main__":
    print("[+] Testing Diffie–Hellman key exchange")

    # Alice
    alice = DHKeyPair()
    # Bob
    bob = DHKeyPair(g=alice.g, p=alice.p)

    # Exchange public values
    Ks_alice = alice.compute_shared_key(bob.public)
    Ks_bob = bob.compute_shared_key(alice.public)

    print("[*] Alice public A:", alice.public)
    print("[*] Bob public B:", bob.public)
    print("[*] Shared key match:", Ks_alice == Ks_bob)
    print("[*] AES key (hex):", Ks_alice.hex())
