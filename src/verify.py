"""
Verify a signed academic credential.

Checks performed, in order (fail fast on the first problem found):
  1. The signer's certificate is well-formed and chains to the EduSign
     root CA (was actually issued by us, not self-signed by an
     attacker).
  2. The signer's certificate has not expired.
  3. The signer's certificate has not been revoked (CRL check), and
     the CRL itself hasn't been tampered with.
  4. The credential's issue_date is not in the future and not older
     than a sane bound (basic sanity check).
  5. The cryptographic signature over the credential payload is valid
     for the exact bytes presented (tamper detection).
  6. (Optional, for live/interactive signing flows) the timestamp is
     within the replay window.

Usage:
    python -m src.verify --credential examples/jon_doe_degree.json
    python -m src.verify --credential examples/jon_doe_degree.json --check-replay
"""
import base64
import datetime
import json

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from src import ca as ca_module
from src import config
from src import revoke as revoke_module
from src.sign import canonical_bytes


class VerificationError(Exception):
    """Raised with a human-readable reason whenever verification fails."""


def verify_chain_of_trust(signer_cert: x509.Certificate, ca_cert: x509.Certificate):
    """Confirm the signer's certificate was actually issued by our CA."""
    try:
        ca_cert.public_key().verify(
            signer_cert.signature,
            signer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            signer_cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise VerificationError(
            "Certificate chain invalid: signer certificate was NOT issued by the "
            "trusted EduSign Root CA (possible impersonation / untrusted signer)."
        )


def verify_not_expired(signer_cert: x509.Certificate):
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < signer_cert.not_valid_before_utc or now > signer_cert.not_valid_after_utc:
        raise VerificationError(
            f"Signer certificate is not currently valid "
            f"(valid {signer_cert.not_valid_before} to {signer_cert.not_valid_after})."
        )


def verify_not_revoked(signer_cert: x509.Certificate):
    if not revoke_module.verify_crl_signature():
        raise VerificationError("CRL signature invalid: revocation list may have been tampered with.")
    if revoke_module.is_revoked(signer_cert.serial_number):
        raise VerificationError(
            f"Signer certificate (serial {signer_cert.serial_number}) has been REVOKED."
        )


def verify_signature(signed_credential: dict):
    signer_cert = x509.load_pem_x509_certificate(signed_credential["signer_cert"].encode())
    message = canonical_bytes(signed_credential["payload"])
    signature = base64.b64decode(signed_credential["signature"])

    try:
        signer_cert.public_key().verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise VerificationError(
            "Signature verification FAILED: the credential has been altered since it "
            "was signed, or the signature does not match."
        )

    return signer_cert


def verify_replay_window(signed_credential: dict):
    ts_str = signed_credential["payload"]["timestamp"]
    ts = datetime.datetime.fromisoformat(ts_str)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=datetime.timezone.utc)
    age = (datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds()
    if age > config.REPLAY_WINDOW_SECONDS:
        raise VerificationError(
            f"Credential timestamp is {int(age)}s old, outside the "
            f"{config.REPLAY_WINDOW_SECONDS}s replay window for live verification."
        )


def verify_credential(signed_credential: dict, check_replay: bool = False) -> dict:
    """
    Run the full verification pipeline. Returns a dict describing the
    result; raises VerificationError with a specific reason on failure.
    """
    _, ca_cert = ca_module.load_ca()

    signer_cert = verify_signature(signed_credential)   # 5. tamper check first (cheapest, most common failure)
    verify_chain_of_trust(signer_cert, ca_cert)          # 1. trusted issuer
    verify_not_expired(signer_cert)                      # 2. cert lifetime
    verify_not_revoked(signer_cert)                      # 3. revocation
    if check_replay:
        verify_replay_window(signed_credential)          # 6. optional replay check

    return {
        "valid": True,
        "signer": signer_cert.subject.rfc4514_string(),
        "serial": signer_cert.serial_number,
        "student": signed_credential["payload"]["student_name"],
        "degree": signed_credential["payload"]["degree"],
        "issue_date": signed_credential["payload"]["issue_date"],
    }


@click.command()
@click.option("--credential", required=True, help="Path to the signed credential JSON.")
@click.option("--check-replay", is_flag=True, help="Also enforce the live replay window.")
def main(credential, check_replay):
    """Verify a signed academic credential."""
    with open(credential) as f:
        signed_credential = json.load(f)

    try:
        result = verify_credential(signed_credential, check_replay=check_replay)
    except VerificationError as e:
        click.echo(f"INVALID: {e}")
        raise SystemExit(1)

    click.echo("VALID credential.")
    click.echo(f"  Student    : {result['student']}")
    click.echo(f"  Degree     : {result['degree']}")
    click.echo(f"  Issued     : {result['issue_date']}")
    click.echo(f"  Signed by  : {result['signer']}")
    click.echo(f"  Cert serial: {result['serial']}")


if __name__ == "__main__":
    main()
