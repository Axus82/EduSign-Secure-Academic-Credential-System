"""
Attack simulation: an attacker captures a validly-signed credential
during a live signing/verification session and re-submits ("replays")
it later, hoping it will be accepted again in a context where only a
fresh, recent signature should be. verify.py's optional replay-window
check must reject stale timestamps. (Long-lived credentials like
degrees intentionally skip this check by default - see below.)
"""
import copy
import datetime

import pytest

from src.verify import verify_credential, VerificationError
from src import config


def test_fresh_credential_passes_replay_check(signed_credential):
    result = verify_credential(signed_credential, check_replay=True)
    assert result["valid"] is True


def test_stale_credential_fails_replay_check(signed_credential):
    stale = copy.deepcopy(signed_credential)
    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=config.REPLAY_WINDOW_SECONDS + 60
    )
    stale["payload"]["timestamp"] = old_time.isoformat()
    # NOTE: this deliberately breaks the signature too (payload changed),
    # so this test on its own doesn't isolate the replay check from the
    # signature check - see test below for that isolation.
    with pytest.raises(VerificationError):
        verify_credential(stale, check_replay=True)


def test_replay_window_isolated_from_signature_check(registrar):
    """
    Re-sign a credential whose *original* timestamp is already outside
    the replay window, so the signature is valid but the timestamp is
    legitimately stale - isolating the replay check from tamper
    detection.
    """
    from src.sign import sign_credential, canonical_bytes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    import base64
    import json

    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=config.REPLAY_WINDOW_SECONDS + 120
    )
    payload = {
        "student_name": "Jon Doe",
        "degree": "BSc Computer Science",
        "institution": "EduSign University",
        "issue_date": "2026-07-01",
        "timestamp": old_time.isoformat(),
        "nonce": "deadbeefdeadbeef",
    }
    message = canonical_bytes(payload)
    signature = registrar["private_key"].sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    from cryptography.hazmat.primitives import serialization
    signed = {
        "payload": payload,
        "signature": base64.b64encode(signature).decode(),
        "signer_cert": registrar["cert"].public_bytes(serialization.Encoding.PEM).decode(),
        "signature_algorithm": "RSA-PSS-SHA256",
    }

    # Signature is genuinely valid...
    result = verify_credential(signed, check_replay=False)
    assert result["valid"] is True

    # ...but replay check correctly rejects the stale timestamp.
    with pytest.raises(VerificationError, match="replay window"):
        verify_credential(signed, check_replay=True)
