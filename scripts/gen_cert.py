#!/usr/bin/env python3
"""
Issue server/client X.509 certificate signed by Root CA.

Usage:
    python3 gen_cert.py --name server
    python3 gen_cert.py --name client

Output:
    ../certs/server.key.pem
    ../certs/server.cert.pem
or:
    ../certs/client.key.pem
    ../certs/client.cert.pem
"""

import os
import argparse
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def issue_certificate(entity_name: str, certs_dir="../certs"):
    """Issue an RSA X.509 certificate signed by the root CA."""
    os.makedirs(certs_dir, exist_ok=True)

    # Paths
    ca_key_path = os.path.join(certs_dir, "root_ca.key.pem")
    ca_cert_path = os.path.join(certs_dir, "root_ca.cert.pem")
    entity_key_path = os.path.join(certs_dir, f"{entity_name}.key.pem")
    entity_cert_path = os.path.join(certs_dir, f"{entity_name}.cert.pem")

    # Ensure CA files exist
    if not (os.path.exists(ca_key_path) and os.path.exists(ca_cert_path)):
        raise FileNotFoundError("Root CA key/cert not found. Run gen_ca.py first.")

    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # 1️⃣ Generate entity private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2️⃣ Define subject info
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bitshift"),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
        ]
    )

    # 3️⃣ Build certificate signed by Root CA
    now = datetime.datetime.utcnow()
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(entity_name)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    # 4️⃣ Sign certificate with CA private key
    cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    # 5️⃣ Write private key
    with open(entity_key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 6️⃣ Write certificate
    with open(entity_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificate issued successfully for '{entity_name}'")
    print(f"    Private Key : {os.path.abspath(entity_key_path)}")
    print(f"    Certificate : {os.path.abspath(entity_cert_path)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Issue server/client cert signed by Root CA.")
    parser.add_argument("--name", required=True, help="Entity name (e.g., server, client)")
    args = parser.parse_args()

    issue_certificate(args.name)
