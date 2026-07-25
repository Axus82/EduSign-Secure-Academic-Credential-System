"""
Sign an academic credential (degree, transcript, certificate) using a
registrar's private key, loaded from a password-protected PKCS#12
keystore.

The signed payload includes a timestamp and a random nonce so that a
captured signed credential cannot be silently replayed in a live
verification session outside its validity window (see verify.py and
tests/test_replay.py).

Usage:
    python -m src.sign --keystore keystore/alice.p12 \
        --student "Jon Doe" --degree "BSc Computer Science" \
        --institution "EduSign University" --out examples/jon_doe_degree.json
"""
import base64
import datetime
import json
import os
import secrets

import click
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

from src import config


def canonical_bytes(payload: dict) -> bytes:
    """
    Deterministic JSON serialisation so signer and verifier always hash
    the exact same bytes (sorted keys, no extra whitespace).
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_keystore(p12_path: str, password: bytes):
    with open(p12_path, "rb") as f:
        p12_data = f.read()
    private_key, cert, ca_certs = pkcs12.load_key_and_certificates(p12_data, password)
    return private_key, cert, ca_certs


def sign_credential(private_key, cert, credential_data: dict) -> dict:
    payload = dict(credential_data)
    payload["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload["nonce"] = secrets.token_hex(16)

    message = canonical_bytes(payload)
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode(),
        "signer_cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "signature_algorithm": "RSA-PSS-SHA256",
    }


@click.command()
@click.option("--keystore", required=True, help="Path to the registrar's .p12 keystore.")
@click.option("--student", required=True)
@click.option("--degree", required=True)
@click.option("--institution", default="EduSign University")
@click.option("--out", required=True, help="Output path for the signed credential JSON.")
def main(keystore, student, degree, institution, out):
    """Sign a new academic credential."""
    import getpass
    password = getpass.getpass(f"Password for {keystore}: ").encode()

    try:
        private_key, cert, _ = load_keystore(keystore, password)
    except Exception:
        click.echo("Failed to open keystore: wrong password or corrupt file.")
        raise SystemExit(1)

    credential_data = {
        "student_name": student,
        "degree": degree,
        "institution": institution,
        "issue_date": datetime.date.today().isoformat(),
    }

    signed = sign_credential(private_key, cert, credential_data)

    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        json.dump(signed, f, indent=2)

    click.echo(f"Credential signed and saved to {out}")
    click.echo(f"  Signer : {cert.subject.rfc4514_string()}")
    click.echo(f"  Serial : {cert.serial_number}")


if __name__ == "__main__":
    main()
