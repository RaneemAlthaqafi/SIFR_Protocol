# Production-and-Proof Quality Gate

Review date: 2026-05-09

Status: **Do not tag a full release yet.** Local tests pass and claims have
been downgraded where evidence is missing, but GitHub CI has not been verified
and several target claims remain future work.

| # | Gate question | Answer | Evidence / downgrade |
|---:|---|---|---|
| 1 | Production security model complete? | Yes | `docs/production_security_model.md` |
| 2 | Secure config defaults implemented? | Yes | `sifr/config.py`, `tests/test_production_config.py` |
| 3 | Fuzz/property tests added? | No | Future work; current evidence is unit/adversarial tests |
| 4 | W3C VC compliance achieved? | No | Downgraded to VC-shaped `SIFRCapabilityCredential` |
| 5 | External VC interoperability passed? | No | Future work |
| 6 | DID compliance profile implemented? | Yes | Documented DID profile only |
| 7 | DID tests passed? | Yes | Included in `293 passed` |
| 8 | Multi-host network evaluation run? | No | Future work |
| 9 | Raw network data committed? | Partial | v0.3 Docker/NetEm data committed; no v0.5 two-network data |
| 10 | Implementation-refinement proof exists? | No | Future work |
| 11 | If not, is claim downgraded to trace conformance? | Yes | `sifr/trace_conformance.py`, tests |
| 12 | Apalache run completed? | No | Operator-runnable config only |
| 13 | Apalache logs committed? | No | Future work |
| 14 | CI green? | Unknown | Local suite green; remote CI not checked |
| 15 | Paper claims match evidence? | Yes | Updated `paper/main.tex` |
| 16 | README claims match evidence? | Yes | Updated `README.md` |
| 17 | No overclaims remain? | Yes, with known downgrades | Hostile review found no remaining release-blocking overclaim |

## Local Verification

```text
SIFR_TLC_FROZEN=1 python -m pytest -q
293 passed in 8.52s
```

```text
python -m pytest --collect-only -q
293 tests collected in 0.42s
```

```text
python examples/demo_secure_quic_wasm_did_flow.py
Demo completed successfully.
```

```text
python examples/demo_v0_3_adversary_cases.py
30 passed in 0.92s
All 30 v0.3 attacks were correctly rejected.
```

## Release Decision

- Full release tag: **No**.
- GitHub release: **No**.
- Research artifact status: **Local release candidate with honest downgraded claims**.
- Required before tagging: push branch, verify CI green, decide whether to run
  the v0.5 Docker/NetEm harness, and regenerate release zips after CI.
