"""
EduSign - shared configuration and filesystem layout.

Centralising paths here keeps every module consistent and makes the
project easy to relocate/package.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CA_DIR = os.path.join(BASE_DIR, "ca_data")
CA_KEY_PATH = os.path.join(CA_DIR, "ca_private.pem")
CA_CERT_PATH = os.path.join(CA_DIR, "ca_cert.pem")
CRL_PATH = os.path.join(CA_DIR, "crl.json")

KEYSTORE_DIR = os.path.join(BASE_DIR, "keystore")

CREDENTIALS_DIR = os.path.join(BASE_DIR, "examples")

# Replay-protection window: a signed credential's timestamp must be
# within this many seconds of "now" for time-sensitive verification
# flows (e.g. live signing sessions). Long-lived credentials such as
# degrees are exempt from this and are checked for validity/expiry
# instead - see verify.py.
REPLAY_WINDOW_SECONDS = 300

os.makedirs(CA_DIR, exist_ok=True)
os.makedirs(KEYSTORE_DIR, exist_ok=True)
os.makedirs(CREDENTIALS_DIR, exist_ok=True)
