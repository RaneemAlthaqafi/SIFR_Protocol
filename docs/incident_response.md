# Incident Response

This runbook covers incidents for the documented SIFR verifier deployment
model. It assumes the operator controls the verifier host and key storage.

## Severity Guide

| Severity | Examples | Immediate action |
|---|---|---|
| SEV-1 | private-key exposure, forged accepted action, revoked capability accepted | stop affected verifier, rotate keys, preserve logs |
| SEV-2 | replay accepted, revocation log tamper detected, WASM policy bypass attempt | isolate verifier, snapshot state, block sender |
| SEV-3 | malformed traffic spike, oversized payload attempts, rate-limit pressure | throttle upstream, retain samples |

## First 15 Minutes

1. Preserve verifier logs, replay SQLite files, revocation JSONL logs, and
   audit-DAG exports.
2. Record current commit, config, host, time range, and affected tenant.
3. Stop demo mode immediately if it is active outside a local test.
4. If key exposure is suspected, revoke the affected key id and rotate keys.
5. If a capability is abused, append a signed revocation entry and reload
   verifier state.
6. Keep error redaction enabled while collecting diagnostics.

## Evidence to Collect

- signed SIFR frames involved in the incident;
- capability grant and credential status objects;
- replay database copy and WAL files;
- signed revocation JSONL log;
- audit-DAG JSONL export;
- verifier config with secrets removed;
- host clock source and NTP status;
- network capture if available.

## Recovery

- Restore only from a known-good key store and revocation log.
- Rotate issuer keys when private-key exposure cannot be ruled out.
- Reset replay state only after the replay window has elapsed or after all
  clients have moved to fresh sessions.
- Re-run:

```powershell
$env:SIFR_TLC_FROZEN='1'
python -m pytest -q
python examples/demo_secure_quic_wasm_did_flow.py
python examples/demo_v0_3_adversary_cases.py
```

## Disclosure Language

Use evidence verbs from `docs/formal_scope.md`. Do not say "fully secure".
Acceptable wording:

> SIFR is production-hardened for the documented deployment model and threat
> model.

Downgrade any property without current test, benchmark, or machine-checkable
evidence to assumed or future work.
