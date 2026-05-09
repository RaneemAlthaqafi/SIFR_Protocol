# Production Security Model

This document defines the deployment and threat model for SIFR production
hardening. It does not claim that SIFR is fully secure. The strongest earned
claim is:

> SIFR is production-hardened for the documented deployment model and threat
> model.

## Deployment Modes

| Mode | Purpose | Required configuration | Claim status |
|---|---|---|---|
| `single_verifier` | One verifier process or one active host. | Non-demo key store, payload limit, replay window, redacted errors. | implemented, tested |
| `clustered_verifier` | Multiple verifier processes sharing local durable state. | Non-demo key store, SQLite replay store, signed revocation log, payload limit, replay window, redacted errors. | implemented, tested for shared filesystem state |
| `multi_tenant_verifier` | Clustered verifier with tenant-scoped configuration. | Clustered requirements plus tenant id. | implemented config guard, assumed isolation by host service |
| `development_demo` | Local examples and fixtures. | Explicit `allow_demo_keys=True`. | implemented, tested |

The implementation surface is `sifr/config.py`. Non-demo modes fail closed
when required key storage is missing or when demo key material is enabled.

## Threat Model

In scope:

- network attackers who can read, replay, drop, delay, or mutate SIFR frames;
- clients that send malformed, oversized, replayed, expired, revoked, or
  unauthorized messages;
- local operator mistakes such as accidentally enabling demo keys in a
  production mode;
- verifier crashes followed by restart when SQLite replay state or JSONL
  revocation logs are configured;
- accidental leakage of secret-bearing exception strings through structured
  error responses.

Out of scope:

- compromise of the verifier host, Python runtime, or private-key storage;
- side-channel attacks against Ed25519, AES-GCM, Argon2id, or SHA-256;
- Byzantine consensus or global revocation propagation;
- arbitrary untrusted-code safety beyond the documented no-WASI WASM policy;
- public Internet-scale availability, DDoS resistance, or enterprise PKI.

## Security Controls

`SIFRConfig.validate()` enforces:

- explicit demo mode before demo keys can be used;
- non-demo key storage in all production modes;
- no `demo:` or demo-named key-store URI in production modes;
- redacted structured errors in production modes;
- bounded payload size, default 1 MiB and maximum 16 MiB;
- configurable replay window, default 300 seconds and maximum 24 hours;
- durable replay and revocation settings for clustered modes;
- tenant id for multi-tenant mode;
- positive optional rate-limit parameters.

`SIFRConfig.enforce_payload_limit()` checks a byte, string, or canonical JSON
payload before processing. `SIFRConfig.build_replay_cache()` applies the
configured replay window to `ReplayCache`. `SIFRConfig.redact_exception()`
returns a JSON-serializable error envelope that hides exception details when
redaction is enabled.

## Evidence

- implemented: `sifr/config.py`
- tested: `tests/test_production_config.py`
- related replay/revocation tests:
  `tests/test_distributed_replay.py`,
  `tests/test_distributed_revocation.py`
- related WASM tests:
  `tests/test_wasm_sandbox_hardening.py`

## Remaining Limitations

- Production rate limiting is configuration only; enforcement belongs in the
  hosting service or reverse proxy.
- Multi-tenant isolation is guarded by configuration, but tenant data-plane
  isolation is assumed from the host service.
- Clustered replay/revocation relies on a shared SQLite database and signed
  JSONL log. It is not distributed consensus and not global revocation.
- CI does not run public-network, NAT, or cloud-region tests.
