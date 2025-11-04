#!/usr/bin/env python3
"""
Create Root CA (RSA + self-signed X.509) using cryptography.

This script generates:
- root_ca.key.pem   (private key — KEEP SECRET)
- root_ca.cert.pem  (self-signed CA certificate)

Stored in ../certs/ by default (create it if missing).
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def create_root_ca(
    ca_name="Bitshift Root CA",
    certs_dir="../certs",
    key_filename="root_ca.key.pem",
    cert_filename="root_ca.cert.pem",
):
    """Generate a root CA private key and self-signed X.509 certificate."""
    os.makedirs(certs_dir, exist_ok=True)

    key_path = os.path.join(certs_dir, key_filename)
    cert_path = os.path.join(certs_dir, cert_filename)

    # 1️⃣ Generate RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2️⃣ Build subject & issuer (same for self-signed cert)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bitshift"),
            x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
        ]
    )

    # 3️⃣ Build the certificate
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))  # ~10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    # 4️⃣ Write private key
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 5️⃣ Write self-signed certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA created successfully.")
    print(f"    Private Key : {os.path.abspath(key_path)}")
    print(f"    Certificate : {os.path.abspath(cert_path)}")


if __name__ == "__main__":
    create_root_ca()
