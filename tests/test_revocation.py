"""
Attack simulation: a registrar's signing key is compromised (or they
are found to have issued fraudulent credentials), so their certificate
is revoked. Any credential they sign - even with a technically valid
signature - must now be rejected by the verifier.
"""
import pytest

from src import revoke as revoke_module
from src.verify import verify_credential, VerificationError


def test_credential_from_active_cert_is_valid(signed_credential):
    result = verify_credential(signed_credential)
    assert result["valid"] is True


def test_credential_from_revoked_cert_is_rejected(signed_credential, registrar):
    serial = registrar["cert"].serial_number

    crl = revoke_module.load_crl_raw()
    crl["revoked_serials"].append(serial)
    revoke_module.save_and_sign_crl(crl)

    with pytest.raises(VerificationError, match="REVOKED"):
        verify_credential(signed_credential)


def test_crl_tampering_is_detected(signed_credential, registrar):
    """
    If an attacker edits the CRL file directly on disk to remove a
    revoked serial (rather than going through revoke.py), the CRL's
    own signature check must catch the tampering.
    """
    import json
    from src import config

    serial = registrar["cert"].serial_number
    crl = revoke_module.load_crl_raw()
    crl["revoked_serials"].append(serial)
    revoke_module.save_and_sign_crl(crl)

    # Attacker directly edits the CRL file, bypassing revoke.py,
    # removing the revocation without re-signing it correctly.
    with open(config.CRL_PATH) as f:
        tampered = json.load(f)
    tampered["revoked_serials"] = []
    with open(config.CRL_PATH, "w") as f:
        json.dump(tampered, f)

    with pytest.raises(VerificationError, match="CRL signature invalid"):
        verify_credential(signed_credential)
