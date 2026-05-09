# DID Methods in SIFR

SIFR implements three DID methods for Ed25519. None of them claims full W3C ecosystem interoperability.

| Method | Resolver | Use |
|---|---|---|
| `did:web` | `sifr.did.did_web.DidWebResolver` | Resolves DIDs via HTTP/HTTPS per the [did:web spec](https://w3c-ccg.github.io/did-method-web/). |
| `did:key` | `sifr.did.did_key.DidKeyResolver` | Pure-cryptographic — the DID identifier itself encodes the public key (Ed25519 only). |
| `did:sifr` | `sifr.did.did_sifr.DidSifrResolver` | Local-only fallback. Resolves DIDs from a directory of JSON documents on disk. |

All three implement the `DidResolver` ABC, which satisfies the `KeyResolver` Protocol. They are interchangeable under `MultiMethodResolver`.

## Honest scope claim

> SIFR supports `did:web`, `did:key`, and local `did:sifr` for Ed25519 keys
> encoded as `publicKeyBase64`, `publicKeyMultibase`, or `publicKeyJwk`.

We do **not** claim full W3C DID-Core compliance, JSON-LD context expansion,
URDNA2015 normalization, support for non-Ed25519 curves, or interoperability
with other registered DID methods (`did:ion`, `did:ethr`, `did:peer`, …).

## Supported DID document schema

All methods accept documents shaped as below. Exactly one of
`publicKeyBase64`, `publicKeyMultibase`, or `publicKeyJwk` must be present
per verificationMethod entry.

```json
{
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:sifr:alice",
    "verificationMethod": [
        {
            "id": "did:sifr:alice#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:sifr:alice",
            "publicKeyMultibase": "z<base58btc(0xed01 || raw32)>"
        }
    ]
}
```

Accepted `type` / key-format combinations:

| `type` | Key field | Notes |
|---|---|---|
| `Ed25519VerificationKey2018` | `publicKeyBase64` | Legacy form, still accepted for compatibility. |
| `Ed25519VerificationKey2020` | `publicKeyBase64` *or* `publicKeyMultibase` | Multibase is the W3C-preferred encoding. |
| `JsonWebKey2020` | `publicKeyJwk` | JWK must have `{"kty":"OKP","crv":"Ed25519","x":<base64url>}`. |

Multibase encoding rules:

- Prefix character `z` selects base58btc.
- Decoded payload must start with multicodec `0xed 0x01` (Ed25519 public key) followed by exactly 32 raw bytes.
- Other multibase prefixes (`m` for base64, `f` for base16, …) are rejected.

JWK encoding rules (RFC 7518 §6.1.2 / RFC 8037 §2):

- `kty` must be `OKP`.
- `crv` must be `Ed25519`.
- `x` must be base64url (no padding) of exactly 32 raw bytes.

## did:web

## did:web

## did:web

Per the [W3C did:web spec](https://w3c-ccg.github.io/did-method-web/), the DID is mapped to an HTTPS URL:

| DID | URL |
|---|---|
| `did:web:example.com` | `https://example.com/.well-known/did.json` |
| `did:web:example.com%3A8080` | `https://example.com:8080/.well-known/did.json` |
| `did:web:example.com:agents:alice` | `https://example.com/agents/alice/did.json` |

The colon between host and port is percent-encoded (`%3A`); subsequent colons are interpreted as path separators.

`DidWebResolver(scheme="http")` is for tests only. Production usage uses HTTPS.

## did:key

`did:key` is purely cryptographic: the DID identifier itself contains the
public key, so resolution is local and deterministic and never touches a
network or filesystem.

Form: `did:key:z<base58btc(0xed01 || raw32)>`. The verificationMethod id is
constructed by appending `#z<multibase>` to the DID, matching the
W3C-CCG canonical form. The resolver verifies that the input identifier is
in canonical form (re-encoding the parsed key produces the same string)
and rejects:

- non-`z` multibase prefixes (`m`, `f`, …);
- multicodec prefixes other than Ed25519 `0xed01`;
- short or extra-byte payloads;
- any DID method other than `did:key`.

The synthesized verificationMethod uses `Ed25519VerificationKey2020` +
`publicKeyMultibase`.

## did:sifr (local method)

SIFR's local DID method. Documents live in a configured directory:

```
docs/
  did_documents/
    alice.json     # contains {"id": "did:sifr:alice", ...}
    bob.json       # contains {"id": "did:sifr:bob", ...}
```

The resolver maps `did:sifr:<name>` → `<root>/<name>.json`. Path traversal sequences (`/`, `\`, `..`) in `<name>` are rejected.

This method exists for offline tests, integration demos, and air-gapped scenarios. It is not interoperable with any external DID ecosystem.

## What we explicitly do NOT claim

- Full W3C DID-Core compliance. SIFR's parser does not load JSON-LD
  contexts and does not perform RDF canonicalization (URDNA2015).
- Support for non-Ed25519 curves (X25519, secp256k1, P-256, …).
- Resolution of `did:ion`, `did:ethr`, `did:peer`, or any DID method beyond
  `did:web`, `did:key`, and `did:sifr`. Adding new methods means writing a
  new `DidResolver` subclass and registering it with `MultiMethodResolver`.
- Long-term identifier persistence. `did:web` documents can disappear when
  the host stops serving them; `did:sifr` documents are local; `did:key` is
  forever-valid but cannot be rotated without a new identifier.

## Trap-acceptance tests

Tests in `tests/test_did_resolution.py` enforce non-trivial properties:

| Test | What it proves |
|---|---|
| `test_did_sifr_kid_not_in_doc` | Resolution looks up the kid in the verificationMethod list, not just the prefix. A doc with `#key-1` does NOT satisfy a request for `#key-2`. |
| `test_did_sifr_controller_mismatch_rejected` | The verificationMethod's `controller` must equal the DID. Otherwise an attacker could embed someone else's key in their own document. |
| `test_did_sifr_path_traversal_rejected` | `did:sifr:../etc/passwd` does NOT resolve to anywhere outside the configured root. |
| `test_did_sifr_wrong_id_in_doc` | A document at `alice.json` whose `id` field says `did:sifr:bob` is rejected. |
| `test_did_web_id_mismatch` | A did:web document fetched at `example.com/.well-known/did.json` whose `id` field disagrees with the DID is rejected. |

These tests prove the resolver is doing real document validation, not string parsing.
