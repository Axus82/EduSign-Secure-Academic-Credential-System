# EduSign — Secure Academic Credential System

EduSign is an open-source PKI-based tool that lets universities issue
digitally-signed academic credentials (degrees, transcripts,
certificates) that anyone can verify instantly and offline, without
contacting the issuing institution. It defends against forged
diplomas, tampered transcripts, and unauthorized issuers, and supports
confidential delivery of transcripts to third parties such as
employers.

Built for ST6051CEM Practical Cryptography.

## Why

Diploma fraud and slow manual verification are real problems for
employers, admissions offices, and licensing bodies. EduSign replaces
"call the registrar's office and wait" with "run one command and get
a cryptographic guarantee."

## Architecture

```
                    ┌─────────────────────┐
                    │   EduSign Root CA    │  (self-signed, offline)
                    └──────────┬───────────┘
                               │ issues certs
                 ┌─────────────┴─────────────┐
                 ▼                            ▼
        ┌─────────────────┐         ┌─────────────────┐
        │ Registrar A cert │         │ Registrar B cert │
        │ (password-locked  │        │ (password-locked  │
        │  PKCS#12 keystore)│        │  PKCS#12 keystore)│
        └────────┬─────────┘         └────────┬─────────┘
                 │ signs                      │ signs
                 ▼                            ▼
        ┌────────────────────────────────────────────┐
        │        Signed Credential (JSON)              │
        │  { payload, signature, signer_cert }          │
        └───────────────────┬────────────────────────┘
                             ▼
                  ┌────────────────────┐
                  │   Verifier          │
                  │ 1. Signature valid? │
                  │ 2. Chains to CA?    │
                  │ 3. Not expired?     │
                  │ 4. Not revoked?     │
                  └────────────────────┘
```

## Cryptographic techniques used

| Purpose | Technique |
|---|---|
| Registrar / CA identity | X.509 certificates, RSA-4096 (CA) / RSA-2048 (registrars) |
| Credential signatures | RSA-PSS with SHA-256 |
| Key storage | Password-protected PKCS#12 keystores |
| Revocation | Signed JSON CRL (CA-signed, tamper-evident) |
| Confidential transcript delivery | Hybrid encryption: AES-256-GCM + RSA-OAEP key wrapping |
| Replay protection | Per-signature timestamp + random nonce, enforced replay window |

## Install

Requires Python 3.10+.

```bash
git clone <this-repo-url>
cd edusign
pip install -r requirements.txt
```

## Usage

### 1. Set up the Certificate Authority (once)

```bash
python -m src.ca init
```

Creates `ca_data/ca_private.pem` (keep secret — this is your root of
trust) and `ca_data/ca_cert.pem` (safe to distribute publicly).

### 2. Issue a registrar certificate

```bash
python -m src.issue_cert --name "Dr. Alice Sharma" --org "EduSign University" --out alice
```

You'll be prompted to set a password. This produces a
password-protected keystore at `keystore/alice.p12` containing the
registrar's private key and their CA-signed certificate.

### 3. Sign a credential

```bash
python -m src.sign --keystore keystore/alice.p12 \
    --student "Jon Doe" --degree "BSc Computer Science" \
    --institution "EduSign University" \
    --out examples/jon_doe_degree.json
```

### 4. Verify a credential

```bash
python -m src.verify --credential examples/jon_doe_degree.json
```

Add `--check-replay` to also enforce the live replay window (useful
for interactive signing sessions rather than long-lived degree
records).

### 5. Revoke a certificate

```bash
python -m src.revoke add --serial <serial-number>
python -m src.revoke list
```

Any credential signed by a revoked certificate will immediately fail
verification, even if it was validly signed before revocation.

### 6. Confidential transcript delivery (hybrid encryption)

```bash
# Encrypt for a specific recipient (needs their public certificate)
python -m src.encrypt_transcript --in transcript.txt \
    --recipient-cert keystore/alice_cert.pem --out transcript.enc.json

# Only the holder of the matching private key can decrypt
python -m src.decrypt_transcript --in transcript.enc.json \
    --recipient-keystore keystore/alice.p12 --out transcript_decrypted.txt
```

## Testing

```bash
pip install pytest
pytest tests/ -v
```

The test suite includes simulated attacks: credential tampering,
revoked-signer rejection, untrusted/self-signed impostor rejection,
replay attacks, wrong-password keystore access, and ciphertext
tampering. Each test is isolated in its own temp CA/keystore
environment (see `tests/conftest.py`) so tests never interfere with
each other or with real project data.

There's also `smoke_test.py` in the repo root, a dependency-free
end-to-end script useful for quick manual sanity checks without
installing pytest.

## Security notes

- The root CA private key should, in a real deployment, live on an
  offline machine or a hardware security module (HSM) — never on a
  network-connected server. This project simulates that separation by
  keeping `ca_data/` isolated from registrar keystores.
- Registrar private keys are never stored unencrypted; PKCS#12 keystore
  passwords are the only thing standing between a stolen `.p12` file
  and the private key.
- Forward secrecy for live transcript-delivery *sessions* (as opposed
  to at-rest encrypted files) would use ephemeral ECDHE key exchange
  per session — see `docs/architecture.md` for the extension design.

## Use cases

See the project report for full detail. In short:

1. **Diploma/transcript verification for employers** — instant
   cryptographic proof of authenticity, no phone calls to the registrar.
2. **Cross-institution credential recognition** — a receiving university
   verifies a transfer student's credentials against the issuing
   university's public CA certificate.
3. **Confidential transcript delivery** — hybrid encryption ensures only
   the intended recipient (e.g. a specific employer) can read a
   transcript in transit.

## Contributing

Contributions welcome. Please:

- Keep functions small and documented (see existing modules for the
  docstring style used throughout).
- Add a test in `tests/` for any new behaviour, especially anything
  security-relevant (attack simulations are highly valued).
- Run `pytest tests/ -v` before opening a PR — CI (`.github/workflows/ci.yml`)
  will run the same suite automatically.
- Open an issue first for any change to the credential JSON schema or
  the certificate profile, since those affect interoperability with
  already-issued credentials.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This is a coursework/educational project. It demonstrates PKI
concepts correctly but has not undergone professional security audit
and should not be used to protect real academic records in production
without further review (e.g. HSM-backed CA key storage, proper
OCSP/CRL distribution infrastructure, rate limiting, and a security
audit).
