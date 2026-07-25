import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import config, ca as ca_module, issue_cert, sign as sign_module


@pytest.fixture()
def isolated_env(tmp_path, monkeypatch):
    """
    Redirect all EduSign file paths into a fresh temp directory so
    tests never touch (or depend on) real project data, and can't
    interfere with each other.
    """
    ca_dir = tmp_path / "ca_data"
    keystore_dir = tmp_path / "keystore"
    examples_dir = tmp_path / "examples"
    ca_dir.mkdir()
    keystore_dir.mkdir()
    examples_dir.mkdir()

    monkeypatch.setattr(config, "CA_DIR", str(ca_dir))
    monkeypatch.setattr(config, "CA_KEY_PATH", str(ca_dir / "ca_private.pem"))
    monkeypatch.setattr(config, "CA_CERT_PATH", str(ca_dir / "ca_cert.pem"))
    monkeypatch.setattr(config, "CRL_PATH", str(ca_dir / "crl.json"))
    monkeypatch.setattr(config, "KEYSTORE_DIR", str(keystore_dir))
    monkeypatch.setattr(config, "CREDENTIALS_DIR", str(examples_dir))

    private_key, cert = ca_module.generate_root_ca()
    ca_module.save_ca(private_key, cert)

    return {"tmp_path": tmp_path}


@pytest.fixture()
def registrar(isolated_env):
    """A legitimate registrar certificate issued by the (isolated) CA."""
    ca_private_key, ca_cert = ca_module.load_ca()

    reg_key = issue_cert.generate_registrar_keypair()
    csr = issue_cert.build_csr(reg_key, common_name="Dr. Alice Sharma", org_name="EduSign University")
    reg_cert = issue_cert.issue_certificate(csr, ca_private_key, ca_cert)

    password = b"test-password-123"
    p12_path = issue_cert.save_keystore(reg_key, reg_cert, ca_cert, "alice_test", password)

    return {
        "private_key": reg_key,
        "cert": reg_cert,
        "p12_path": p12_path,
        "password": password,
    }


@pytest.fixture()
def signed_credential(registrar):
    """A validly-signed sample credential from the registrar fixture above."""
    return sign_module.sign_credential(
        registrar["private_key"],
        registrar["cert"],
        {
            "student_name": "Jon Doe",
            "degree": "BSc Computer Science",
            "institution": "EduSign University",
            "issue_date": "2026-07-20",
        },
    )
