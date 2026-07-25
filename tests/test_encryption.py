"""
Confidentiality tests for the hybrid encryption module:
  1. A legitimate round trip (encrypt -> decrypt) recovers the exact
     plaintext.
  2. A recipient who is NOT the intended recipient (wrong private key)
     cannot decrypt the envelope.
  3. Ciphertext tampering is caught by AES-GCM's built-in authentication
     tag, so silent corruption/tampering never produces "valid-looking"
     garbage output.
"""
import pytest

from src.encrypt_transcript import encrypt_file
from src.decrypt_transcript import decrypt_file
from src import issue_cert
from src import ca as ca_module


@pytest.fixture()
def second_registrar(isolated_env):
    """A second, unrelated keypair to act as a 'wrong recipient'."""
    ca_private_key, ca_cert = ca_module.load_ca()
    key = issue_cert.generate_registrar_keypair()
    csr = issue_cert.build_csr(key, common_name="Employer Bob", org_name="Bob Corp")
    cert = issue_cert.issue_certificate(csr, ca_private_key, ca_cert)
    return {"private_key": key, "cert": cert}


def test_round_trip_recovers_plaintext(registrar):
    plaintext = b"Transcript: Jon Doe, BSc Computer Science, GPA 3.9"
    envelope = encrypt_file(plaintext, registrar["cert"].public_key())

    recovered = decrypt_file(envelope, registrar["private_key"])
    assert recovered == plaintext


def test_wrong_recipient_cannot_decrypt(registrar, second_registrar):
    plaintext = b"Confidential transcript data"
    envelope = encrypt_file(plaintext, registrar["cert"].public_key())  # encrypted FOR registrar

    with pytest.raises(Exception):
        decrypt_file(envelope, second_registrar["private_key"])  # bob tries to open it


def test_tampered_ciphertext_is_rejected(registrar):
    import base64

    plaintext = b"Transcript data that must not be silently corrupted"
    envelope = encrypt_file(plaintext, registrar["cert"].public_key())

    raw = bytearray(base64.b64decode(envelope["ciphertext"]))
    raw[0] ^= 0xFF  # flip bits in the ciphertext
    envelope["ciphertext"] = base64.b64encode(bytes(raw)).decode()

    with pytest.raises(Exception):
        decrypt_file(envelope, registrar["private_key"])
