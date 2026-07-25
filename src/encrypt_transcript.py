"""
Hybrid encryption for confidential transcript delivery.

Why hybrid? RSA alone can only encrypt small payloads (bounded by key
size) and is slow for bulk data. Instead we:
  1. Generate a random AES-256 key (fast, handles any file size).
  2. Encrypt the transcript with AES-256-GCM (confidentiality + built
     in integrity/authentication via the GCM tag).
  3. Encrypt (wrap) the AES key itself with the recipient's RSA public
     key using OAEP padding.
  4. Ship {wrapped_key, nonce, ciphertext, tag} to the recipient - only
     someone holding the matching RSA private key can recover the AES
     key and thus the plaintext.

Usage:
    python -m src.encrypt_transcript --in transcript.txt \
        --recipient-cert keystore/employer_cert.pem --out transcript.enc.json
    python -m src.decrypt_transcript --in transcript.enc.json \
        --recipient-keystore keystore/employer.p12 --out transcript_decrypted.txt
"""
import base64
import json
import os

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(plaintext: bytes, recipient_public_key) -> dict:
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    wrapped_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    return {
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "algorithm": "AES-256-GCM + RSA-OAEP-SHA256",
    }


@click.command()
@click.option("--in", "in_path", required=True, help="Plaintext transcript file to encrypt.")
@click.option("--recipient-cert", required=True, help="PEM certificate of the recipient (contains their public key).")
@click.option("--out", required=True, help="Output path for the encrypted envelope JSON.")
def main(in_path, recipient_cert, out):
    """Encrypt a transcript for a specific recipient."""
    with open(in_path, "rb") as f:
        plaintext = f.read()

    with open(recipient_cert, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    envelope = encrypt_file(plaintext, cert.public_key())

    with open(out, "w") as f:
        json.dump(envelope, f, indent=2)

    click.echo(f"Transcript encrypted for {cert.subject.rfc4514_string()}")
    click.echo(f"  Output: {out}")


if __name__ == "__main__":
    main()
