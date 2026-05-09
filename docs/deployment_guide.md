# Deployment Guide

This guide describes how to run SIFR with the production configuration
guardrails in `sifr/config.py`.

## Required Steps

1. Choose a deployment mode:
   - `single_verifier`
   - `clustered_verifier`
   - `multi_tenant_verifier`
   - `development_demo`
2. Configure non-demo key storage for every non-demo mode.
3. Configure payload and replay-window limits.
4. Keep structured error redaction enabled in non-demo modes.
5. For clustered and multi-tenant modes, configure durable replay and
   revocation state.

## Environment Variables

| Variable | Required | Meaning |
|---|---:|---|
| `SIFR_MODE` | no | Defaults to `single_verifier`. |
| `SIFR_KEY_STORE_URI` | yes outside demo | URI/path for protected key storage. |
| `SIFR_REPLAY_STORE_URI` | clustered modes | SQLite replay database path. |
| `SIFR_REVOCATION_LOG_URI` | clustered modes | Signed JSONL revocation log path. |
| `SIFR_MAX_PAYLOAD_BYTES` | no | Default `1048576`; maximum `16777216`. |
| `SIFR_REPLAY_WINDOW_SECONDS` | no | Default `300`; maximum `86400`. |
| `SIFR_REDACT_ERRORS` | no | Must remain true outside demo. |
| `SIFR_ALLOW_DEMO_KEYS` | demo only | Must be true only in `development_demo`. |
| `SIFR_DEMO_KEY_IDS` | demo only | Comma-separated fixture key ids. |
| `SIFR_TENANT_ID` | multi-tenant | Tenant identifier. |
| `SIFR_RATE_LIMIT_RPM` | no | Optional rate-limit hint. |
| `SIFR_RATE_LIMIT_BURST` | no | Optional burst hint. |
| `SIFR_RATE_LIMIT_DISABLED` | no | Disables rate-limit hints if true. |

## Single Verifier

```powershell
$env:SIFR_MODE = "single_verifier"
$env:SIFR_KEY_STORE_URI = "file:///var/lib/sifr/keystore.json"
$env:SIFR_MAX_PAYLOAD_BYTES = "1048576"
$env:SIFR_REPLAY_WINDOW_SECONDS = "300"
```

Claim status: implemented and tested for local verifier configuration.

## Clustered Verifier

```powershell
$env:SIFR_MODE = "clustered_verifier"
$env:SIFR_KEY_STORE_URI = "file:///var/lib/sifr/keystore.json"
$env:SIFR_REPLAY_STORE_URI = "C:\\sifr-state\\replay.sqlite3"
$env:SIFR_REVOCATION_LOG_URI = "C:\\sifr-state\\revocations.jsonl"
```

The replay store uses SQLite WAL mode and the revocation log is signed JSONL.
This is process-shared durable state, not consensus.

Claim status: implemented and tested for shared local durable state.

## Multi-Tenant Verifier

```powershell
$env:SIFR_MODE = "multi_tenant_verifier"
$env:SIFR_TENANT_ID = "tenant-a"
$env:SIFR_KEY_STORE_URI = "file:///var/lib/sifr/tenant-a/keystore.json"
$env:SIFR_REPLAY_STORE_URI = "C:\\sifr-state\\tenant-a\\replay.sqlite3"
$env:SIFR_REVOCATION_LOG_URI = "C:\\sifr-state\\tenant-a\\revocations.jsonl"
```

The config layer requires a tenant id. Isolation between tenants must be
enforced by the hosting service's storage, process, network, and access-control
boundaries.

Claim status: implemented config guard; host isolation is assumed.

## Development/Demo Mode

```powershell
$env:SIFR_MODE = "development_demo"
$env:SIFR_ALLOW_DEMO_KEYS = "true"
$env:SIFR_DEMO_KEY_IDS = "did:sifr:demo#key-1"
```

Demo mode is the only mode that permits demo keys. It is not a production
deployment mode.

## Startup Check

Applications should call:

```python
from sifr.config import SIFRConfig

config = SIFRConfig.from_env()
```

If configuration is missing or unsafe, `ConfigError` is raised before the
verifier accepts traffic.
