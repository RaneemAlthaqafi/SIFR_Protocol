# Cryptographic Assumptions and Test Vectors

SIFR uses standard cryptographic primitives. **SIFR does not prove primitive
security from scratch.** It validates integration against published standard
test vectors and relies on the standard cryptographic assumptions stated below.

## Honest claim

> We do not prove primitive security; we validate integration against standard
> vectors and rely on standard cryptographic assumptions.

If any of these assumptions is broken in the literature, the affected SIFR
guarantee inherits that weakness.

## Primitives in use

| Primitive | Where used in SIFR | Standard / Specification |
|---|---|---|
| Ed25519 (EdDSA over Curve25519, SHA-512) | All message signatures, capability-grant signatures, capability-revocation signatures, credential proofs | RFC 8032; FIPS 186-5 |
| SHA-256 | Content IDs (CIDs) for messages and audit-DAG nodes | FIPS 180-4 |
| AES-256-GCM | Optional symmetric encryption of frame bodies (transport-level confidentiality) | NIST SP 800-38D; FIPS 197 |
| Argon2id | Password-based key derivation for the local at-rest keyring (`sifr/key_management.py`) | RFC 9106 |

## Assumption 1 — Ed25519 unforgeability

We assume Ed25519 (RFC 8032) is existentially unforgeable under
chosen-message attack (EUF-CMA) in the random-oracle model with the discrete
log assumption on Curve25519. Brendel–Cremers–Jackson–Zhao (Crypto 2021)
formalize the variant played by RFC 8032; we adopt their statement.

**Implication for SIFR.** If Ed25519 is EUF-CMA secure, an attacker without
access to the private key cannot produce a fresh `(message, signature)` pair
that passes verification, except with negligible probability. Therefore:

- A `CapabilityGrant` cannot be forged for a different subject.
- A `CapabilityRevocation` cannot be forged on behalf of an issuer.
- A signed SIFR frame cannot be transplanted under a different `sender_id` and
  still verify (the signature binds the canonical-JSON encoding which includes
  `sender_id`).

This assumption is not proven by SIFR. We rely on it.

## Assumption 2 — SHA-256 collision and second-preimage resistance

We assume SHA-256 (FIPS 180-4) is collision-resistant and second-preimage
resistant. No collision has been published as of 2024; the best generic attack
remains 2^128 effort.

**Implication for SIFR.** Audit-DAG node CIDs uniquely identify a node's
canonical bytes. An adversary cannot construct a different node with the same
CID, so tampering with a node's body invalidates parent links that reference
its old CID.

## Assumption 3 — AES-256-GCM authenticated-encryption

We assume AES-256-GCM, when used with a 96-bit nonce, key length 256 bits,
and *unique nonce per key*, provides both confidentiality (IND-CCA) and
ciphertext integrity (INT-CTXT). The IV-uniqueness assumption is critical:
nonce reuse with the same key catastrophically breaks GCM authentication
(Joux, 2006; Böck–Zauner–Devlin–Somorovsky–Jovanovic, 2016).

**Implication for SIFR.** Where SIFR uses AES-GCM, the caller must guarantee
nonce uniqueness. SIFR documents this as a *caller responsibility* and
provides API misuse tests that detect:

- AES-GCM verification fails when AAD is altered.
- AES-GCM verification fails when ciphertext is altered.
- AES-GCM verification fails when tag is altered.

SIFR does **not** automatically generate nonces; the caller must use a
counter or random 96-bit nonce per key. This is documented and tested.

## Assumption 4 — Argon2id password-hashing security

We assume Argon2id (RFC 9106) with parameters at least
`(t=2, m=64 MiB, p=1, salt_len=16, tag_len=32)` resists offline password
recovery for moderate-strength passwords. RFC 9106 §4 recommends these as
minimum interactive-class parameters; we exceed them.

**Implication for SIFR.** Local at-rest keyrings encrypt private keys with a
key derived from a passphrase via Argon2id. An adversary who steals the
encrypted keyring file but not the passphrase cannot trivially recover keys.

The *Argon2id parameters used at encryption time* are recorded in the
encrypted keyring blob and re-applied verbatim at decryption. This is tested.

## Test vectors validated

`tests/test_crypto_vectors.py` runs the following vectors at import time of
the relevant primitive in the project's environment:

| Source | Vectors used |
|---|---|
| RFC 8032 §7.1 | Ed25519 TEST 1, TEST 2, TEST 3 (sign + verify equality) |
| FIPS 180-4 / NIST CAVS | SHA-256 of empty string, "abc", and the 56-character message; longer 1-million-`a` vector via streaming update |
| NIST SP 800-38D Appendix B | AES-128-GCM and AES-256-GCM Test Case 1, 3, 4 (encrypt+decrypt+tag check) |
| RFC 9106 §A.3 | Argon2id reference vector with declared parameters |

Any future change to a crypto dependency that breaks one of these vectors
will fail `pytest tests/test_crypto_vectors.py`.

## Misuse-resistance tests

In addition to vector parity, we assert misuse resistance:

- `test_ed25519_wrong_key_rejected`: verifying with the wrong public key fails.
- `test_ed25519_modified_message_rejected`: flipping any byte of the message
  invalidates the signature.
- `test_aes_gcm_wrong_aad_rejected`: AAD mismatch yields `InvalidTag`.
- `test_aes_gcm_modified_ciphertext_rejected`: any ciphertext bit flip yields
  `InvalidTag`.
- `test_aes_gcm_nonce_reuse_documented`: documents that nonce reuse with the
  same key is catastrophic and verifies the API requires explicit nonce
  passing (no default-nonce footgun).
- `test_argon2id_parameters_recorded_and_verified`: hashing twice with the
  same parameters yields a verifying tag; a parameter mismatch fails.

## What this section does *not* claim

- It does not claim a cryptographic proof of any primitive.
- It does not claim quantum-resistance.
- It does not claim that the wider Python `cryptography` and `argon2-cffi`
  libraries are formally verified. Those libraries are widely used and
  audited; SIFR depends on their correctness.
- It does not claim resistance to side-channel attacks against the host
  process.

## References

- D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, B. Yang. "High-speed
  high-security signatures." J. Cryptographic Engineering, 2012.
- S. Josefsson, I. Liusvaara. RFC 8032: *Edwards-Curve Digital Signature
  Algorithm (EdDSA)*. IETF, 2017.
- J. Brendel, C. Cremers, D. Jackson, M. Zhao. "The Provable Security of
  Ed25519: Theory and Practice." S&P 2021 / Crypto 2021.
- NIST. FIPS PUB 180-4: *Secure Hash Standard (SHS)*. 2015.
- NIST. SP 800-38D: *Recommendation for Block Cipher Modes of Operation:
  Galois/Counter Mode (GCM) and GMAC*. 2007.
- NIST. FIPS PUB 197: *Advanced Encryption Standard (AES)*. 2001.
- A. Biryukov, D. Dinu, D. Khovratovich, S. Josefsson. RFC 9106:
  *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
  Applications*. IETF, 2021.
- A. Joux. "Authentication failures in NIST version of GCM." 2006.
- H. Böck, A. Zauner, S. Devlin, J. Somorovsky, P. Jovanovic. "Nonce-Disrespecting
  Adversaries: Practical Forgery Attacks on GCM in TLS." WOOT 2016.
