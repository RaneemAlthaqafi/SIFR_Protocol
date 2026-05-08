# DID Methods in SIFR

SIFR v0.2 implements two DID methods. Neither claims full W3C interoperability.

| Method | Resolver | Use |
|---|---|---|
| `did:web` | `sifr.did.did_web.DidWebResolver` | Primary. Resolves DIDs via HTTP/HTTPS per the [did:web spec](https://w3c-ccg.github.io/did-method-web/). |
| `did:sifr` | `sifr.did.did_sifr.DidSifrResolver` | Local-only fallback. Resolves DIDs from a directory of JSON documents on disk. |

Both implement the `DidResolver` ABC, which itself satisfies the `KeyResolver` Protocol. They are interchangeable under `MultiMethodResolver`.

## Supported DID document schema

Both methods consume documents with this structure:

```json
{
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:sifr:alice",
    "verificationMethod": [
        {
            "id": "did:sifr:alice#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:sifr:alice",
            "publicKeyBase64": "<32-byte Ed25519 public key, base64>"
        }
    ]
}
```

Supported `type` values: `Ed25519VerificationKey2020`, `Ed25519VerificationKey2018`. The key field is `publicKeyBase64` (a SIFR-specific simplification — the full W3C spec uses `publicKeyMultibase` or `publicKeyJwk`).

## did:web

Per the [W3C did:web spec](https://w3c-ccg.github.io/did-method-web/), the DID is mapped to an HTTPS URL:

| DID | URL |
|---|---|
| `did:web:example.com` | `https://example.com/.well-known/did.json` |
| `did:web:example.com%3A8080` | `https://example.com:8080/.well-known/did.json` |
| `did:web:example.com:agents:alice` | `https://example.com/agents/alice/did.json` |

The colon between host and port is percent-encoded (`%3A`); subsequent colons are interpreted as path separators.

`DidWebResolver(scheme="http")` is for tests only. Production usage uses HTTPS.

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

- Compatibility with the wider W3C DID ecosystem. SIFR's parser does not load JSON-LD contexts, does not perform RDF canonicalization, and supports only one verificationMethod field name (`publicKeyBase64`).
- Resolution of `did:key`, `did:ion`, `did:ethr`, or any other registered method. Adding new methods means writing a new `DidResolver` subclass and registering it with `MultiMethodResolver`.
- Long-term identifier persistence guarantees. `did:web` documents can disappear when the host stops serving them; `did:sifr` documents are local and not synchronized.

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
