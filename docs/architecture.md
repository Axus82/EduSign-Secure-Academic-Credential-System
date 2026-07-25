# EduSign Architecture Notes

## Trust model

EduSign uses a single-tier PKI: one root CA signs registrar
certificates directly. Real-world deployments would typically use a
two-tier model (offline root CA signs one or more online
intermediate/issuing CAs), which limits the blast radius if an
issuing CA is compromised — the root never needs to be brought online
to revoke it. This project uses a single tier to keep the codebase
focused on the assessed learning outcomes; the extension to a
two-tier model only requires adding one more `CertificateBuilder`
step with `ca=True` and issuing registrar certs from the intermediate
instead of the root.

## Credential data model

```json
{
  "payload": {
    "student_name": "Jon Doe",
    "degree": "BSc Computer Science",
    "institution": "EduSign University",
    "issue_date": "2026-07-25",
    "timestamp": "2026-07-25T15:59:51.575077+00:00",
    "nonce": "5acfde17566975df48b33b53d93425e5"
  },
  "signature": "<base64 RSA-PSS-SHA256 signature over canonical JSON of payload>",
  "signer_cert": "<PEM-encoded X.509 certificate>",
  "signature_algorithm": "RSA-PSS-SHA256"
}
```

`payload` is serialised deterministically (sorted keys, no
whitespace) before signing/verifying, so signer and verifier always
hash identical bytes regardless of JSON library formatting quirks.

## Revocation

A full X.509 CRL or OCSP responder is out of scope for the assessed
timeframe. Instead, EduSign uses a minimal JSON CRL
(`ca_data/crl.json`) containing a list of revoked serial numbers,
itself signed by the CA. The verifier:

1. Checks the CRL's own signature (so an attacker can't just delete a
   serial from the file to "un-revoke" a compromised registrar).
2. Checks whether the signer's serial number appears in the list.

This gives the same security property as a real CRL (revoked keys are
rejected) with far less infrastructure.

## Forward secrecy extension (design, not implemented in the CLI)

The brief asks for forward secrecy in *encrypted communications*. The
current `encrypt_transcript.py` module encrypts data **at rest**
(a file, once) using a fresh random AES key each time — this already
means compromising one transcript's key doesn't expose any other
transcript. True *session* forward secrecy (protecting live, ongoing
communication even if a long-term private key is later stolen)
requires an ephemeral key exchange per session:

1. Sender and recipient each generate a fresh ECDHE (Elliptic Curve
   Diffie-Hellman Ephemeral) keypair for this session only.
2. They exchange ephemeral public keys (optionally signing them with
   their long-term certificate to prevent MITM — this is exactly what
   TLS 1.3 does).
3. Both derive a shared session key via ECDH; the session key never
   touches disk and is discarded after the session.
4. Even if a long-term private key is later compromised, past session
   keys cannot be reconstructed, because they were never derived from
   long-term key material alone — each session's ephemeral keys are
   randomly generated and never stored.

This is noted as a natural "future work" item in the report — a full
implementation would add a `session.py` module using
`cryptography.hazmat.primitives.asymmetric.ec` (`generate_private_key(ec.SECP256R1())`)
plus HKDF for session key derivation.

## MITM mitigation

- Every registrar certificate is checked against the trusted root CA
  before its signature is trusted — an attacker presenting their own
  keypair without a CA-issued certificate is rejected
  (`test_unauthorized_signer.py`).
- In any real network transport (e.g. a REST API wrapping this CLI),
  TLS would additionally protect the channel itself; EduSign's PKI
  operates at the application/document layer, on top of that.
