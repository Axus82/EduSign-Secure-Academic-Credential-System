"""
Certificate revocation for EduSign.

Implements a minimal Certificate Revocation List (CRL): a JSON file
listing revoked certificate serial numbers, signed by the CA so it
can't be tampered with in transit. In production you'd use a real
X.509 CRL or OCSP; this simplified version demonstrates the same
security property (revoked keys are rejected) without the extra
tooling overhead.

Usage:
    python -m src.revoke list
    python -m src.revoke add --serial 123456789
"""
import base64
import json

import click
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from src import ca as ca_module
from src import config


def load_crl_raw() -> dict:
    with open(config.CRL_PATH) as f:
        return json.load(f)


def save_and_sign_crl(crl_data: dict):
    """Sign the CRL contents with the CA key and store the signature alongside it."""
    ca_private_key, _ = ca_module.load_ca()

    revoked_list = sorted(crl_data["revoked_serials"])
    message = json.dumps(revoked_list, sort_keys=True).encode()
    signature = ca_private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    crl_data["revoked_serials"] = revoked_list
    crl_data["crl_signature"] = base64.b64encode(signature).decode()

    with open(config.CRL_PATH, "w") as f:
        json.dump(crl_data, f, indent=2)


def is_revoked(serial_number: int) -> bool:
    crl = load_crl_raw()
    return serial_number in crl.get("revoked_serials", [])


def verify_crl_signature() -> bool:
    """Confirm the CRL itself hasn't been tampered with."""
    _, ca_cert = ca_module.load_ca()
    crl = load_crl_raw()

    if "crl_signature" not in crl:
        return True  # empty/untouched CRL, nothing to verify yet

    signature = base64.b64decode(crl["crl_signature"])
    message = json.dumps(sorted(crl["revoked_serials"]), sort_keys=True).encode()

    try:
        ca_cert.public_key().verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


@click.group()
def cli():
    """Manage the EduSign certificate revocation list."""


@cli.command()
@click.option("--serial", required=True, type=int, help="Certificate serial number to revoke.")
def add(serial):
    """Revoke a registrar certificate by serial number."""
    crl = load_crl_raw()
    if serial in crl["revoked_serials"]:
        click.echo("Serial already revoked.")
        return
    crl["revoked_serials"].append(serial)
    save_and_sign_crl(crl)
    click.echo(f"Serial {serial} revoked and CRL re-signed.")


@cli.command(name="list")
def list_revoked():
    """List all revoked certificate serial numbers."""
    crl = load_crl_raw()
    if not crl["revoked_serials"]:
        click.echo("No certificates revoked.")
        return
    for s in crl["revoked_serials"]:
        click.echo(s)


if __name__ == "__main__":
    cli()
