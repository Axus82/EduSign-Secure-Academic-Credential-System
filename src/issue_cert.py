"""
Issue an X.509 certificate for a registrar (a person/office authorised
to sign academic credentials on behalf of an institution).

Flow:
  1. Generate a fresh keypair for the registrar.
  2. Build a Certificate Signing Request (CSR).
  3. The CA signs the CSR, producing a certificate chained to the root.
  4. The registrar's private key + certificate are bundled into a
     password-protected PKCS#12 keystore (.p12), simulating secure key
     storage (an HSM would do the equivalent without ever exposing the
     raw key material).

Usage:
    python -m src.issue_cert --name "Dr. Alice Sharma" --org "EduSign University" --out alice
"""
import datetime
import getpass
import os

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from src import ca as ca_module
from src import config


def generate_registrar_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_csr(private_key, common_name, org_name):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return csr


def issue_certificate(csr, ca_private_key, ca_cert, valid_days=365):
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,      # signing credentials
                content_commitment=True,     # non-repudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert


def save_keystore(private_key, cert, ca_cert, out_name, password: bytes):
    """Bundle registrar key + cert + CA cert into a password-protected .p12 file."""
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=out_name.encode(),
        key=private_key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    p12_path = os.path.join(config.KEYSTORE_DIR, f"{out_name}.p12")
    with open(p12_path, "wb") as f:
        f.write(p12_bytes)
    os.chmod(p12_path, 0o600)
    return p12_path


@click.command()
@click.option("--name", required=True, help="Registrar's full name / common name.")
@click.option("--org", default="EduSign University", help="Institution name.")
@click.option("--out", required=True, help="Output keystore filename (without extension).")
@click.option("--days", default=365, help="Certificate validity in days.")
def main(name, org, out, days):
    """Issue a new registrar certificate and password-protected keystore."""
    if not os.path.exists(config.CA_KEY_PATH):
        click.echo("No CA found. Run 'python -m src.ca init' first.")
        raise SystemExit(1)

    ca_private_key, ca_cert = ca_module.load_ca()

    registrar_key = generate_registrar_keypair()
    csr = build_csr(registrar_key, common_name=name, org_name=org)
    cert = issue_certificate(csr, ca_private_key, ca_cert, valid_days=days)

    password = getpass.getpass(f"Set a keystore password for {out}.p12: ").encode()
    confirm = getpass.getpass("Confirm password: ").encode()
    if password != confirm:
        click.echo("Passwords did not match.")
        raise SystemExit(1)

    p12_path = save_keystore(registrar_key, cert, ca_cert, out, password)

    click.echo("Registrar certificate issued.")
    click.echo(f"  Subject   : {cert.subject.rfc4514_string()}")
    click.echo(f"  Serial    : {cert.serial_number}")
    click.echo(f"  Valid til : {cert.not_valid_after_utc}")
    click.echo(f"  Keystore  : {p12_path}  (password-protected)")


if __name__ == "__main__":
    main()
