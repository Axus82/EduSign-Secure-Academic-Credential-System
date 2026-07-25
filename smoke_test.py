"""
Manual end-to-end smoke test (no pytest required) - exercises every
module and every attack simulation, printing PASS/FAIL for each. This
is purely a development sanity check; the real test suite for grading
purposes is in tests/ (run with `pytest tests/ -v`).
"""
import base64
import copy
import datetime
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

results = []

def check(name, condition):
    status = "PASS" if condition else "FAIL"
    results.append((name, status))
    print(f"[{status}] {name}")


# Redirect config to a temp dir so this doesn't pollute the real project data
tmp = tempfile.mkdtemp()
from src import config
config.CA_DIR = os.path.join(tmp, "ca_data")
config.CA_KEY_PATH = os.path.join(config.CA_DIR, "ca_private.pem")
config.CA_CERT_PATH = os.path.join(config.CA_DIR, "ca_cert.pem")
config.CRL_PATH = os.path.join(config.CA_DIR, "crl.json")
config.KEYSTORE_DIR = os.path.join(tmp, "keystore")
os.makedirs(config.CA_DIR, exist_ok=True)
os.makedirs(config.KEYSTORE_DIR, exist_ok=True)

from src import ca as ca_module
from src import issue_cert
from src import sign as sign_module
from src import verify as verify_module
from src import revoke as revoke_module
from src import encrypt_transcript, decrypt_transcript

# --- 1. CA setup ---
ca_key, ca_cert = ca_module.generate_root_ca()
ca_module.save_ca(ca_key, ca_cert)
check("CA created", os.path.exists(config.CA_KEY_PATH) and os.path.exists(config.CA_CERT_PATH))

# --- 2. Issue a registrar cert ---
reg_key = issue_cert.generate_registrar_keypair()
csr = issue_cert.build_csr(reg_key, "Dr. Alice Sharma", "EduSign University")
reg_cert = issue_cert.issue_certificate(csr, ca_key, ca_cert)
password = b"correct-horse-battery-staple"
p12_path = issue_cert.save_keystore(reg_key, reg_cert, ca_cert, "alice", password)
check("Registrar certificate issued", reg_cert.subject.rfc4514_string().find("Alice") != -1)
check("Keystore file created", os.path.exists(p12_path))

# --- 3. Sign a credential ---
credential_data = {
    "student_name": "Jon Doe",
    "degree": "BSc Computer Science",
    "institution": "EduSign University",
    "issue_date": "2026-07-20",
}
signed = sign_module.sign_credential(reg_key, reg_cert, credential_data)
check("Credential signed", "signature" in signed and "payload" in signed)

# --- 4. Verify valid credential ---
result = verify_module.verify_credential(signed)
check("Valid credential verifies successfully", result["valid"] is True and result["student"] == "Jon Doe")

# --- 5. Tamper detection ---
tampered = copy.deepcopy(signed)
tampered["payload"]["degree"] = "PhD Everything"
try:
    verify_module.verify_credential(tampered)
    check("Tampered credential rejected", False)
except verify_module.VerificationError:
    check("Tampered credential rejected", True)

# --- 6. Unauthorized / self-signed impostor ---
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

impostor_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Registrar")])
now = datetime.datetime.now(datetime.timezone.utc)
impostor_cert = (
    x509.CertificateBuilder()
    .subject_name(subj).issuer_name(subj)
    .public_key(impostor_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
    .sign(impostor_key, hashes.SHA256())
)
fake_signed = sign_module.sign_credential(impostor_key, impostor_cert, credential_data)
try:
    verify_module.verify_credential(fake_signed)
    check("Untrusted self-signed signer rejected", False)
except verify_module.VerificationError as e:
    check("Untrusted self-signed signer rejected", "trusted EduSign Root CA" in str(e))

# --- 7. Revocation ---
crl = revoke_module.load_crl_raw()
crl["revoked_serials"].append(reg_cert.serial_number)
revoke_module.save_and_sign_crl(crl)
try:
    verify_module.verify_credential(signed)
    check("Revoked signer's credential rejected", False)
except verify_module.VerificationError as e:
    check("Revoked signer's credential rejected", "REVOKED" in str(e))

# un-revoke for later steps
crl = revoke_module.load_crl_raw()
crl["revoked_serials"] = []
revoke_module.save_and_sign_crl(crl)

# --- 8. Wrong keystore password ---
try:
    sign_module.load_keystore(p12_path, b"wrong-password")
    check("Wrong keystore password rejected", False)
except Exception:
    check("Wrong keystore password rejected", True)

# --- 9. Replay window ---
stale_payload = dict(credential_data)
old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=config.REPLAY_WINDOW_SECONDS + 120)
stale_payload["timestamp"] = old_time.isoformat()
stale_payload["nonce"] = "deadbeef" * 4
message = sign_module.canonical_bytes(stale_payload)
from cryptography.hazmat.primitives.asymmetric import padding
sig = reg_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
from cryptography.hazmat.primitives import serialization
stale_signed = {
    "payload": stale_payload,
    "signature": base64.b64encode(sig).decode(),
    "signer_cert": reg_cert.public_bytes(serialization.Encoding.PEM).decode(),
    "signature_algorithm": "RSA-PSS-SHA256",
}
ok_without_replay_check = verify_module.verify_credential(stale_signed, check_replay=False)["valid"]
try:
    verify_module.verify_credential(stale_signed, check_replay=True)
    replay_rejected = False
except verify_module.VerificationError:
    replay_rejected = True
check("Stale signature still cryptographically valid (sanity)", ok_without_replay_check is True)
check("Replay window correctly rejects stale timestamp", replay_rejected)

# --- 10. Hybrid encryption round trip ---
plaintext = b"CONFIDENTIAL TRANSCRIPT: Jon Doe, GPA 3.9"
envelope = encrypt_transcript.encrypt_file(plaintext, reg_cert.public_key())
recovered = decrypt_transcript.decrypt_file(envelope, reg_key)
check("Hybrid encryption round-trip recovers plaintext", recovered == plaintext)

# --- 11. Wrong recipient cannot decrypt ---
bob_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
try:
    decrypt_transcript.decrypt_file(envelope, bob_key)
    check("Wrong recipient cannot decrypt", False)
except Exception:
    check("Wrong recipient cannot decrypt", True)

# --- 12. Ciphertext tampering detected (GCM auth tag) ---
tampered_envelope = copy.deepcopy(envelope)
raw = bytearray(base64.b64decode(tampered_envelope["ciphertext"]))
raw[0] ^= 0xFF
tampered_envelope["ciphertext"] = base64.b64encode(bytes(raw)).decode()
try:
    decrypt_transcript.decrypt_file(tampered_envelope, reg_key)
    check("Tampered ciphertext rejected (GCM tag)", False)
except Exception:
    check("Tampered ciphertext rejected (GCM tag)", True)

shutil.rmtree(tmp, ignore_errors=True)

print()
passed = sum(1 for _, s in results if s == "PASS")
print(f"{passed}/{len(results)} checks passed")
if passed != len(results):
    sys.exit(1)
