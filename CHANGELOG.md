# Changelog

## [Unreleased] — v0.2.0-dev

### Pre-phase refactor (no behavior change)
- Extract canonicalization helpers (`message_to_canonical_bytes`, `_without_signature`, `canonical_json`) into `sifr/canonical.py`. Re-exported from `sifr.crypto` for backwards compatibility.
- Add `sifr/keyring_iface.py` with `KeyResolver` Protocol and `RevocationInfo` dataclass.
- `crypto.verify_message` now accepts either an `Ed25519PublicKey` or a `KeyResolver`. Direct-key callers unchanged.
- Split `sifr/transport.py` into a package: `sifr/transport/_base.py` (Transport ABC), `sifr/transport/local.py` (LocalTransport, HttpJsonBaselineTransport). `sifr.transport` re-exports all three names.
- Bump version to `0.2.0-dev`.
- Add base deps: `argon2-cffi`, `httpx`, `aioquic`, `wasmtime`.
- Add optional dep groups: `keyring`, `formal-tools`, `dev`.
- Add minimal GitHub Actions CI: pytest on Ubuntu + Windows, Python 3.11 and 3.12.

## [0.1.0] — feasibility prototype
- Signed typed frames (Ed25519), capability grants with budgets, content-addressed audit DAG.
- Two-agent vertical slice over `LocalTransport`.
- 27 tests, 5 benchmarks, IEEE-style paper.
