"""
EduSign Root Certificate Authority.

Generates a self-signed root CA keypair and certificate. In a real
deployment this key would live on an offline machine or HSM; here we
simulate that by keeping it in its own directory, separate from every
registrar keystore, and documenting that it must never be distributed.

Usage:
    python -m src.ca init
"""
import datetime
import os
import sys

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src import config


def generate_root_ca(common_name: str = "EduSign Root CA",
                      org_name: str = "EduSign University Consortium",
                      valid_days: int = 3650):
    """Create a new self-signed root CA keypair + certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,   # allowed to sign other certificates
                crl_sign=True,        # allowed to sign the CRL
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return private_key, cert


def save_ca(private_key, cert):
    with open(config.CA_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(config.CA_KEY_PATH, 0o600)  # root key: owner read/write only

    with open(config.CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Initialise an empty CRL if one doesn't exist yet
    if not os.path.exists(config.CRL_PATH):
        import json
        with open(config.CRL_PATH, "w") as f:
            json.dump({"revoked_serials": []}, f, indent=2)


def load_ca():
    """Load the CA private key and certificate from disk."""
    with open(config.CA_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(config.CA_CERT_PATH, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return private_key, cert


@click.group()
def cli():
    """EduSign Root CA management."""


@cli.command()
@click.option("--common-name", default="EduSign Root CA")
@click.option("--force", is_flag=True, help="Overwrite an existing CA.")
def init(common_name, force):
    """Initialise a new root CA (run this once)."""
    if os.path.exists(config.CA_KEY_PATH) and not force:
        click.echo(f"CA already exists at {config.CA_KEY_PATH}. Use --force to overwrite.")
        sys.exit(1)

    private_key, cert = generate_root_ca(common_name=common_name)
    save_ca(private_key, cert)

    click.echo("Root CA created.")
    click.echo(f"  Private key : {config.CA_KEY_PATH}  (keep offline/secret!)")
    click.echo(f"  Certificate : {config.CA_CERT_PATH}  (distribute this publicly)")
    click.echo(f"  Subject     : {cert.subject.rfc4514_string()}")
    click.echo(f"  Serial      : {cert.serial_number}")
    click.echo(f"  Valid until : {cert.not_valid_after_utc}")


if __name__ == "__main__":
    cli()
