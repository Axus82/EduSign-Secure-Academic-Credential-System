"""
Decrypt a transcript envelope produced by encrypt_transcript.py.

Only the holder of the matching RSA private key (unlocked from their
password-protected .p12 keystore) can recover the original plaintext.
"""
import base64
import getpass
import json

import click
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import pkcs12


def decrypt_file(envelope: dict, private_key) -> bytes:
    wrapped_key = base64.b64decode(envelope["wrapped_key"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


@click.command()
@click.option("--in", "in_path", required=True, help="Encrypted envelope JSON.")
@click.option("--recipient-keystore", required=True, help="Recipient's .p12 keystore.")
@click.option("--out", required=True, help="Output path for the decrypted plaintext.")
def main(in_path, recipient_keystore, out):
    """Decrypt a transcript envelope."""
    with open(in_path) as f:
        envelope = json.load(f)

    password = getpass.getpass(f"Password for {recipient_keystore}: ").encode()
    with open(recipient_keystore, "rb") as f:
        p12_data = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(p12_data, password)

    try:
        plaintext = decrypt_file(envelope, private_key)
    except Exception:
        click.echo("Decryption FAILED: wrong key, or ciphertext has been tampered with (GCM auth failure).")
        raise SystemExit(1)

    with open(out, "wb") as f:
        f.write(plaintext)

    click.echo(f"Decrypted successfully -> {out}")


if __name__ == "__main__":
    main()
