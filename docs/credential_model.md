# SIFR Capability Credentials

SIFR ships **SIFR Capability Credentials** — signed authorization tokens
carrying a capability grant. The data model mirrors the W3C [Verifiable
Credentials Data Model 1.1](https://www.w3.org/TR/vc-data-model/) shape for
ergonomic familiarity. The implementation does NOT claim W3C VC compliance.

## Honest scope claim

> SIFR Capability Credentials are signed Ed25519 grants whose JSON body
> resembles a W3C Verifiable Credential. They are NOT W3C VC compliant: we
> do not load JSON-LD contexts, we do not perform URDNA2015 RDF
> canonicalization, and we use a SIFR-specific `SIFRStatusList2021`
> mechanism that is modeled on but not interoperable with W3C
> StatusList2021.

The primary type is `SIFRCapabilityCredential`. Issued credentials retain
`VerifiableCredential` and `CapabilityCredential` in the type array as
recognizable shape hints — they do NOT signal W3C compliance.

## Data model

```json
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://sifr.dev/contexts/sifr-credential-v1"
    ],
    "type": [
        "VerifiableCredential",
        "CapabilityCredential",
        "SIFRCapabilityCredential"
    ],
    "issuer": "did:sifr:alice",
    "issuanceDate": "2026-05-08T13:24:11Z",
    "expirationDate": "2026-05-08T13:34:11Z",
    "credentialSubject": {
        "id": "did:sifr:bob",
        "capability": {
            "capability_id": "cap_001",
            "issuer": "did:sifr:alice",
            "subject": "did:sifr:bob",
            "actions": ["tool.calculator.add"],
            "resource_scope": ["calculator"],
            "issued_at": "...",
            "expires_at": "...",
            "budget": {"max_calls": 5, "max_payload_bytes": 1024},
            "constraints": {"allow_delegation": false}
        }
    },
    "credentialStatus": {
        "id": "https://sifr.dev/lists/alice-revocation#42",
        "type": "SIFRStatusList2021",
        "statusPurpose": "revocation",
        "statusListIndex": 42,
        "statusListCredential": "https://sifr.dev/lists/alice-revocation"
    },
    "proof": {
        "type": "Ed25519Signature2020",
        "created": "2026-05-08T13:24:11Z",
        "verificationMethod": "did:sifr:alice#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "<base64 Ed25519 signature>"
    }
}
```

The `credentialStatus` field is optional and bound into the proof signature.
It is interpreted by `sifr.credential_status.StatusList`.

The `credentialSubject.capability` payload is exactly the SIFR `CapabilityGrant` payload from `sifr.capabilities.create_capability_grant`. `credential_to_grant()` extracts it after verification.

## Verification rules

`verify_credential(credential, issuer_key)` enforces, in order:

1. `proof` must be a dict with `type == "Ed25519Signature2020"` and `proofPurpose == "assertionMethod"`.
2. The `issuer_key` is either an `Ed25519PublicKey` (used directly) or a `KeyResolver` (used to resolve `proof.verificationMethod` to a key).
3. The DID portion of `proof.verificationMethod` (everything before `#`) must equal the `issuer` field. This blocks credentials that claim issuance by someone whose key didn't actually sign them.
4. The signature is verified over `canonical_json(credential without proof)`. Any mutation of any field outside `proof` invalidates the signature.
5. Date checks: `issuanceDate <= now < expirationDate`.
6. `credentialSubject` must contain `id` and `capability`.

## What we explicitly do NOT claim

- W3C VC compliance. The proof is verified using SIFR's plain canonical-JSON canonicalization (`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`), not the W3C-registered URDNA2015 RDF normalization required by the formal `Ed25519Signature2020` proof suite.
- JSON-LD context handling. We ship a SIFR context document at
  `docs/contexts/sifr-credential-v1.jsonld` for offline inspection but do
  not load it, do not perform expansion/compaction, and do not enforce
  JSON-LD type constraints at runtime.
- W3C StatusList2021 compliance. SIFR's `SIFRStatusList2021` is a
  bitmap-based credential-status mechanism modeled on StatusList2021. It
  uses the same conceptual fields (`statusListIndex`,
  `statusListCredential`) but does NOT use the StatusList2021 wire format
  (no GZIP+base64-multibase encoding, no `StatusList2021Credential` type).
- Holder presentation, schema validation, or `evidence` field handling.
- Cryptographic suites other than Ed25519.

## Trap-acceptance tests

In `tests/test_credentials.py`:

| Test | What it proves |
|---|---|
| `test_mutate_subject_id_after_sign_fails` | Changing `credentialSubject.id` AFTER signing fails verification. |
| `test_mutate_expiration_after_sign_fails` | Extending `expirationDate` after signing fails verification. |
| `test_mutate_capability_after_sign_fails` | Adding actions to the embedded grant fails verification. |
| `test_swap_proof_value_fails` | Modifying `proof.proofValue` directly fails verification. |
| `test_issuer_did_must_match_verification_method` | Signing with one DID's key while claiming issuance from another is rejected. |
| `test_credential_signed_by_wrong_key_rejected` | Verifying with the wrong key fails. |

These are the discriminating tests for "real verifiable credential" vs. "renamed signed grant."

## Pairing with revocation

Credentials answer "is this grant valid?" — but a grant can be revoked AFTER issuance. The full authorization flow uses both:

```python
verify_credential(cred, did_resolver)
grant_payload = credential_to_grant(cred)
# ... package as a CapabilityGrant message and run authorize_action with
# revocation_registry= and replay_cache=.
```

`authorize_action` in `sifr/capabilities.py` accepts both `revocation_registry` and `replay_cache` kwargs.
