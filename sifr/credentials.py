"""SIFR Capability Credentials.

These are signed authorization tokens carrying a capability grant. The data
model mirrors the W3C Verifiable Credentials Data Model 1.1 shape
(@context, type, issuer, issuanceDate, expirationDate, credentialSubject,
proof) for ergonomic familiarity. SIFR does NOT claim W3C VC compliance:

- We do not load JSON-LD contexts or perform RDF canonicalization (URDNA2015).
- The proof type "Ed25519Signature2020" is verified via plain JSON
  canonicalization (sorted keys, separators), with `proofValue` omitted
  from the signed bytes. It is not the W3C-registered proof-suite
  normalization.
- We provide a SIFR-specific `SIFRStatusList2021` mechanism in
  `sifr.credential_status`. It is modeled on, but not compatible with, the
  W3C StatusList2021 wire format.

The `type` array now carries `"SIFRCapabilityCredential"` as the primary
SIFR-native type. `"VerifiableCredential"` and `"CapabilityCredential"` are
retained for backwards compatibility with v0.4 fixtures and demos and for
recognizability by tooling that expects the VC shape — they do NOT signal
W3C compliance.

See docs/credential_model.md for the full scope and non-claims.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json
from .errors import CredentialError
from .keyring_iface import KeyResolver
from .utils import parse_utc, utc_now_iso

IssuerKey = Union[Ed25519PublicKey, KeyResolver]

__all__ = [
    "issue_credential",
    "verify_credential",
    "credential_to_grant",
    "SIFR_CAPABILITY_CREDENTIAL_TYPE",
    "SIFR_CONTEXT_URL",
]

PROOF_TYPE = "Ed25519Signature2020"
PROOF_PURPOSE = "assertionMethod"

# SIFR-native type. The primary type going forward.
SIFR_CAPABILITY_CREDENTIAL_TYPE = "SIFRCapabilityCredential"

# A SIFR-local context URL. This is a plain identifier — SIFR does NOT load
# or expand JSON-LD contexts. The URL is documented in docs/credential_model.md
# and is also written to docs/contexts/sifr-credential-v1.jsonld for offline
# inspection.
SIFR_CONTEXT_URL = "https://sifr.dev/contexts/sifr-credential-v1"


def issue_credential(
    *,
    issuer: str,
    subject: str,
    capability_grant_payload: dict[str, Any],
    issuer_private_key: Ed25519PrivateKey,
    issuer_kid: str,
    expires_at: str,
    issued_at: Optional[str] = None,
    credential_status: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    issuance_date = issued_at or utc_now_iso()
    credential: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            SIFR_CONTEXT_URL,
        ],
        "type": [
            "VerifiableCredential",
            "CapabilityCredential",
            SIFR_CAPABILITY_CREDENTIAL_TYPE,
        ],
        "issuer": issuer,
        "issuanceDate": issuance_date,
        "expirationDate": expires_at,
        "credentialSubject": {
            "id": subject,
            "capability": copy.deepcopy(capability_grant_payload),
        },
    }
    if credential_status is not None:
        # Bind the status reference into the signed body so the (index, list)
        # link cannot be swapped after the fact.
        credential["credentialStatus"] = copy.deepcopy(credential_status)
    credential["proof"] = {
        "type": PROOF_TYPE,
        "created": issuance_date,
        "verificationMethod": issuer_kid,
        "proofPurpose": PROOF_PURPOSE,
    }
    signed_body = copy.deepcopy(credential)
    signed_body["proof"] = dict(credential["proof"])
    body_canonical = canonical_json(signed_body)
    signature = issuer_private_key.sign(body_canonical)
    credential["proof"]["proofValue"] = base64.b64encode(signature).decode("ascii")
    return credential


# A status-checker callable: given the credentialStatus dict, raise
# CredentialError if revoked. SIFR's reference implementation lives in
# sifr.credential_status.StatusList; users can also pass a custom callable.
StatusChecker = Callable[[dict[str, Any]], None]


def verify_credential(
    credential: dict[str, Any],
    issuer_key: IssuerKey,
    *,
    now: Optional[datetime] = None,
    status_checker: Optional[StatusChecker] = None,
) -> bool:
    proof = credential.get("proof")
    if not isinstance(proof, dict):
        raise CredentialError("credential missing proof")
    if proof.get("type") != PROOF_TYPE:
        raise CredentialError(f"unsupported proof type: {proof.get('type')}")
    if proof.get("proofPurpose") != PROOF_PURPOSE:
        raise CredentialError(
            f"proofPurpose must be {PROOF_PURPOSE!r}, got {proof.get('proofPurpose')!r}"
        )
    proof_value = proof.get("proofValue")
    verification_method = proof.get("verificationMethod")
    if not isinstance(proof_value, str) or not isinstance(verification_method, str):
        raise CredentialError("proof missing proofValue or verificationMethod")

    if isinstance(issuer_key, Ed25519PublicKey):
        public_key: Ed25519PublicKey = issuer_key
    else:
        public_key = issuer_key.resolve(verification_method)

    issuer = credential.get("issuer")
    if not isinstance(issuer, str):
        raise CredentialError("credential missing issuer")
    if "#" in verification_method:
        vm_did = verification_method.split("#", 1)[0]
        if vm_did != issuer:
            raise CredentialError(
                f"verificationMethod DID {vm_did!r} does not match issuer {issuer!r}"
            )

    body = copy.deepcopy(credential)
    body["proof"] = copy.deepcopy(proof)
    body["proof"].pop("proofValue", None)
    canonical = canonical_json(body)
    try:
        public_key.verify(base64.b64decode(proof_value), canonical)
    except (InvalidSignature, ValueError) as exc:
        raise CredentialError("credential signature invalid") from exc

    nowdt = now or datetime.now(timezone.utc)
    issuance = parse_utc(credential["issuanceDate"])
    expiration = parse_utc(credential["expirationDate"])
    if nowdt < issuance:
        raise CredentialError("credential not yet valid")
    if nowdt >= expiration:
        raise CredentialError("credential expired")

    subject_obj = credential.get("credentialSubject")
    if not isinstance(subject_obj, dict) or "id" not in subject_obj:
        raise CredentialError("credentialSubject missing id")
    if "capability" not in subject_obj:
        raise CredentialError("credentialSubject missing capability")

    if status_checker is not None:
        status_field = credential.get("credentialStatus")
        if isinstance(status_field, dict):
            # Delegating raises CredentialError on revocation.
            status_checker(status_field)

    return True


def credential_to_grant(credential: dict[str, Any]) -> dict[str, Any]:
    """Extract the embedded capability payload from a credential.

    Caller is responsible for verifying the credential first; this function
    does NOT re-verify.
    """
    subj = credential.get("credentialSubject", {})
    if "capability" not in subj:
        raise CredentialError("credentialSubject missing capability")
    return copy.deepcopy(subj["capability"])
