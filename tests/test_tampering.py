"""
Attack simulation: an attacker intercepts a validly-signed credential
and modifies a field (e.g. changes the degree classification) before
forwarding it on. EduSign must detect this and reject verification.
"""
import copy

import pytest

from src.verify import verify_credential, VerificationError


def test_valid_credential_passes(signed_credential):
    result = verify_credential(signed_credential)
    assert result["valid"] is True
    assert result["student"] == "Jon Doe"


def test_tampered_field_is_rejected(signed_credential):
    tampered = copy.deepcopy(signed_credential)
    tampered["payload"]["degree"] = "PhD Computer Science"  # attacker upgrades their own degree

    with pytest.raises(VerificationError, match="Signature verification FAILED"):
        verify_credential(tampered)


def test_tampered_student_name_is_rejected(signed_credential):
    tampered = copy.deepcopy(signed_credential)
    tampered["payload"]["student_name"] = "Someone Else"

    with pytest.raises(VerificationError):
        verify_credential(tampered)


def test_tampered_signature_bytes_is_rejected(signed_credential):
    tampered = copy.deepcopy(signed_credential)
    # Flip characters in the base64 signature itself
    sig = list(tampered["signature"])
    sig[0] = "A" if sig[0] != "A" else "B"
    tampered["signature"] = "".join(sig)

    with pytest.raises(VerificationError):
        verify_credential(tampered)
