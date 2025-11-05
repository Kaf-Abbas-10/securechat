#!/usr/bin/env python3
"""
RSA PKCS#1 v1.5 SHA-256 sign/verify helpers.

Usage:
    from app.crypto import sign

    # Sign a message
    sig = sign.sign_data(b"hello", "certs/client.key.pem")

    # Verify the signature
    ok = sign.verify_data(b"hello", sig, "certs/client.cert.pem")
"""

import base64
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.PublicKey import RSA


def load_private_key(path: str):
    """Load an RSA private key from PEM file."""
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(path: str):
    """Load RSA public key from a PEM certificate or key file."""
    data = open(path, "rb").read()
    try:
        return RSA.import_key(data)
    except ValueError:
        # If it's a certificate file, extract public key via cryptography
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(data)
        return RSA.import_key(
            cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def sign_data(data: bytes, private_key_path: str) -> bytes:
    """
    Sign data with RSA PKCS#1 v1.5 using SHA-256.
    Returns signature (bytes).
    """
    key = load_private_key(private_key_path)
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature


def verify_data(data: bytes, signature: bytes, public_key_path: str) -> bool:
    """
    Verify RSA PKCS#1 v1.5 signature using SHA-256.
    Returns True if valid, raises ValueError if invalid.
    """
    key = load_public_key(public_key_path)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        raise ValueError("Signature verification failed")


def sign_data_b64(data: bytes, private_key_path: str) -> str:
    """Convenience: return Base64-encoded signature."""
    return base64.b64encode(sign_data(data, private_key_path)).decode()


def verify_data_b64(data: bytes, sig_b64: str, public_key_path: str) -> bool:
    """Verify a Base64-encoded signature."""
    return verify_data(data, base64.b64decode(sig_b64), public_key_path)


# --- CLI Testing Helper ---
if __name__ == "__main__":
    import os

    priv = "../certs/client.key.pem"
    pub = "../certs/client.cert.pem"

    if not os.path.exists(priv) or not os.path.exists(pub):
        print("[!] Run scripts/gen_cert.py --name client first.")
        exit(1)

    message = b"test message for RSA signature"
    print("[+] Signing test message...")

    sig = sign_data(message, priv)
    print(f"Signature (hex): {sig.hex()[:40]}...")

    ok = verify_data(message, sig, pub)
    print(f"Verification result: {ok}")
