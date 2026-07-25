"""
Attack simulation: an attacker who has NOT been issued a certificate
by the EduSign CA generates their own keypair and a self-signed (or
otherwise untrusted) certificate, then signs a fake credential. The
verifier must reject it because the certificate does not chain to the
trusted root CA - this is the core guarantee PKI provides over "bare"
digital signatures.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.sign import sign_credential
from src.verify import verify_credential, VerificationError


def make_self_signed_impostor():
    """Simulate an attacker with their own keypair and a fake, self-signed certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Fake Registrar"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not A Real University"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def test_untrusted_self_signed_signer_is_rejected(isolated_env):
    impostor_key, impostor_cert = make_self_signed_impostor()

    fake_credential = sign_credential(
        impostor_key,
        impostor_cert,
        {
            "student_name": "Jon Doe",
            "degree": "PhD Everything",
            "institution": "EduSign University",
            "issue_date": "2026-07-20",
        },
    )

    with pytest.raises(VerificationError, match="NOT issued by the trusted EduSign Root CA"):
        verify_credential(fake_credential)


def test_legitimate_registrar_still_passes_after_impostor_test(signed_credential):
    """Sanity check: rejecting impostors doesn't accidentally break real signers."""
    result = verify_credential(signed_credential)
    assert result["valid"] is True
