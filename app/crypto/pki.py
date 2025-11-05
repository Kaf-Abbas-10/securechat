#!/usr/bin/env python3
"""
X.509 validation utilities:
- Verify certificate is signed by trusted CA.
- Check validity window (not before / not after).
- Check Common Name (CN) or SubjectAltName (SAN).

Usage:
    from app.crypto import pki
    ok = pki.verify_certificate("certs/client.cert.pem", "certs/root_ca.cert.pem", expected_cn="client")
"""

import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_certificate(path: str) -> x509.Certificate:
    """Load an X.509 certificate from PEM file."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_certificate(
    cert_path: str,
    ca_cert_path: str,
    expected_cn: str | None = None,
    allow_expired: bool = False,
) -> bool:
    """
    Verify that a certificate is:
    - Signed by the given CA certificate
    - Within its validity window
    - Matches expected CN or SAN (if provided)

    Returns True if valid; raises ValueError with reason otherwise.
    """

    # Ensure files exist
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate not found: {cert_path}")
    if not os.path.exists(ca_cert_path):
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")

    # Load certificates
    cert = load_certificate(cert_path)
    ca_cert = load_certificate(ca_cert_path)

    # 1️⃣ Signature verification (ensure cert signed by CA)
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError(f"BAD CERT: signature verification failed ({e})")

    # 2️⃣ Validity period check
    now = datetime.datetime.utcnow()
    if not allow_expired:
        if now < cert.not_valid_before:
            raise ValueError(f"BAD CERT: not yet valid (valid from {cert.not_valid_before})")
        if now > cert.not_valid_after:
            raise ValueError(f"BAD CERT: certificate expired (expired {cert.not_valid_after})")

    # 3️⃣ CN or SAN check
    if expected_cn:
        # Extract CN
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = None

        # Extract SANs if present
        try:
            sans = [
                name.value
                for ext in cert.extensions
                if isinstance(ext.value, x509.SubjectAlternativeName)
                for name in ext.value.get_values_for_type(x509.DNSName)
            ]
        except Exception:
            sans = []

        if cn != expected_cn and expected_cn not in sans:
            raise ValueError(
                f"BAD CERT: CN/SAN mismatch (expected '{expected_cn}', got CN='{cn}', SAN={sans})"
            )

    return True


def fingerprint(cert_path: str) -> str:
    """Compute SHA256 fingerprint of a certificate (for transcripts)."""
    cert = load_certificate(cert_path)
    return cert.fingerprint(hashes.SHA256()).hex()


# --- CLI Testing Helper ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Verify X.509 certificate against CA.")
    parser.add_argument("--cert", required=True, help="Path to certificate to verify")
    parser.add_argument("--ca", required=True, help="Path to root CA certificate")
    parser.add_argument("--cn", help="Expected Common Name")
    args = parser.parse_args()

    try:
        if verify_certificate(args.cert, args.ca, args.cn):
            print(f"[+] Certificate OK: {args.cert}")
    except Exception as e:
        print(f"[!] Verification failed: {e}")
