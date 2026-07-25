"""
Attack simulation: an attacker who has stolen a registrar's .p12
keystore file (e.g. from a lost laptop) tries to open it without
knowing the password. This must fail - the private key inside must
stay protected even if the file itself is exposed.
"""
import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

from src.sign import load_keystore


def test_correct_password_opens_keystore(registrar):
    private_key, cert, ca_certs = load_keystore(registrar["p12_path"], registrar["password"])
    assert cert.serial_number == registrar["cert"].serial_number


def test_wrong_password_fails(registrar):
    with pytest.raises(Exception):
        load_keystore(registrar["p12_path"], b"totally-wrong-password")
