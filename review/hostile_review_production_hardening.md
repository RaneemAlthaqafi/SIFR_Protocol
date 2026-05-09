# Hostile Review: Production-and-Proof Hardening Sprint

Review date: 2026-05-09

Verdict: **Pass with mandatory downgrades.** The repository now contains
production-hardening guardrails, broader DID profile support, stronger
SIFR-native credential/status tests, process-shared replay/revocation,
WASM sandbox hardening, trace-invariant checks, and refreshed paper/README
wording. It does not earn W3C VC compliance, Internet-scale evaluation,
implementation-refinement proof, or Apalache-proven status.

## Claim Review

| Claim | Verdict | Evidence | Limitation |
|---|---|---|---|
| Production security hardening for documented model | tested | `sifr/config.py`, `tests/test_production_config.py`, `docs/production_security_model.md` | Not full security; not HSM/PKI/DDoS/host-compromise coverage |
| W3C VC compatibility | future work | SIFR-native `SIFRCapabilityCredential` tests pass | No JSON-LD loader, URDNA2015, W3C proof suite, Bitstring/StatusList interop, or external verifier |
| Broader DID compliance profile | tested | `did:web`, `did:key`, `did:sifr`; base64, multibase, JWK; relationship checks | Documented profile only, not full DID Core ecosystem |
| Distributed replay/revocation | tested | SQLite-WAL replay, signed JSONL revocation, cross-process tests | No consensus, no global propagation, no multi-writer revocation-log locking |
| WASM sandbox hardening | tested | no-WASI, fuel, memory cap where supported, fresh Store, seven fixtures | Not arbitrary untrusted-code safety; structured evidence is last-call only |
| Network evaluation | benchmarked / future work | v0.3 committed Docker/NetEm delay/loss CSV; v0.5 two-bridge harness | No v0.5 two-network CSV; no multi-host or Internet-scale run |
| Implementation refinement | future work | Trace invariant conformance exists | No machine-checked simulation/refinement proof |
| Apalache invariants | symbolic-checkable | `formal/apalache.cfg` and test for config presence | No Apalache run log committed |
| TLC invariants | bounded-proven | `tlc_metadata.json`: 9 invariants, 11,601 states, depth 7 | Finite constants only |
| Tamarin lemmas | symbolic-proven | `tamarin_metadata.json`: 5/5 lemmas, zero warnings | Dolev-Yao abstraction; replay lemma relies on accepted-once restriction |

## Required Hostile Checks

- Apalache claims backed by logs? **No.** Correct downgrade: symbolic-checkable/operator-runnable only.
- VC compliance backed by external interop? **No.** Correct downgrade: VC-shaped SIFR-native credential.
- DID compliance bounded to a profile? **Yes.**
- Network evaluation actually run or harness only? **Mixed.** v0.3 delay/loss measured; v0.5 two-bridge seven-profile harness only.
- Production security tied to a threat model? **Yes.**
- WASM evidence overclaims? **No remaining overclaim found.**
- Replay/revocation claims consensus? **No.**
- Paper says "fully secure" as a claim? **No.**
- README matches paper? **Yes, after downgrades.**
- Tests pass from this workspace? **Yes:** `SIFR_TLC_FROZEN=1 python -m pytest -q` -> `293 passed in 8.52s`.

## Residual Risks

- CI was not checked through GitHub during this sprint.
- No release tag should be created until CI is green on the remote branch.
- The v0.5 network harness was not run in this environment.
- Figure regeneration used committed benchmark data only; it did not create
  new measurements.

Final hostile verdict: **release candidate for honest research artifact
changes, not a full production/security-compliance release.**
