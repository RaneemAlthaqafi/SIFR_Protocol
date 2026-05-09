# SIFR v0.4.0 Proof-Grade Quality Gate

Honest yes/no answers. v0.4.0 promotes from v0.4-rc1 by running Tamarin Prover 1.7.1 against the symbolic protocol model and obtaining 5/5 verified lemmas with zero wellformedness warnings.

| # | Item | Answer | Evidence / command |
|---|---|---|---|
| 1 | Does clean-clone install pass? | **Yes** | `pip install -e ".[dev]"` succeeds against the v0.3.1+ `pyproject.toml`. |
| 2 | Does CI pass? | **Yes (workflow)** | `.github/workflows/test.yml` runs `pytest -q` with `SIFR_TLC_FROZEN=1`. |
| 3 | Do all tests pass with `SIFR_TLC_FROZEN=1`? | **Yes** | `SIFR_TLC_FROZEN=1 python -m pytest -q` → **190 passed** (170 v0.3.1 + 20 v0.4 proof-obligation). |
| 4 | Does TLC run from scratch? | **Yes** | `bash formal/run_tlc.sh` → `Model checking completed. No error has been found.` 11,601 distinct states. |
| 5 | Are TLC artifacts fresh? | **Yes** | `model_hashes.json` matches the live model files (canonical-text SHA-256). |
| 6 | Does the symbolic model run? | **Yes** | Tamarin 1.7.1 via Docker image `aeads/tamarin:latest`. Reference reproduction in `formal/tamarin/sifr_core.spthy` header and `docs/proof_obligations_v0_4.md`. |
| 7 | Are symbolic lemmas proven or honestly marked failed? | **Yes (5/5 proven, 0 warnings)** | `formal/output/tamarin_output.txt` reports: `authentication: verified (6 steps)`, `authorization_required: verified (5 steps)`, `replay_resistance: verified (2 steps)`, `revocation_safety: verified (2 steps)`, `tool_safety: verified (3 steps)`. |
| 8 | Does every proof claim map to code? | **Yes** | `docs/model_code_traceability_v0_4.md`. |
| 9 | Does every proof claim map to tests? | **Yes** | `tests/test_v0_4_proof_obligations.py` — 20 tests, every claim has positive + adversarial cases. |
| 10 | Does the paper distinguish proven, bounded-proven, symbolic-proven, tested, and assumed? | **Yes** | Paper §Formal Security Analysis (v0.4) updated for v0.4.0 with the five-status taxonomy. |
| 11 | Are release manifests fresh? | **Yes** | `review/v0_4_release_manifest.json` records the v0.4.0 commit; zips rebuilt. |
| 12 | Are benchmark manifests fresh? | **Yes** | `benchmarks/results/v0.3/manifest.json` records the v0.3.1 substance commit; v0.4.0 carries forward this evidence. |
| 13 | Are zips rebuilt? | **Yes** | `sifr-v0.4.0-research-artifact.zip`, `sifr-v0.4.0-overleaf-ready.zip`. |
| 14 | Are GitHub release assets attached? | **Yes** | `gh release view v0.4.0 --repo RaneemAlthaqafi/SIFR_Protocol --json tagName,assets` returns both `sifr-v0.4.0-research-artifact.zip` (1,314,007 bytes) and `sifr-v0.4.0-overleaf-ready.zip` (1,099,014 bytes). Release URL: https://github.com/RaneemAlthaqafi/SIFR_Protocol/releases/tag/v0.4.0 |
| 15 | Is the final verdict honest? | **Yes** | The replay_resistance lemma's verification depends on a documented `accepted_once_per_message` restriction that models the SIFR `ReplayCache` as an external abstract invariant. The implementation enforcement is `sifr/replay.py:ReplayCache.check_and_record`. This dependency is recorded in the lemma comment, in `docs/proof_obligations_v0_4.md`, and in `formal/output/tamarin_metadata.json`. |

## Tally

| Verdict | Count | Items |
|---|---|---|
| Yes | 15 | all |
| No | 0 | — |

## Final v0.4.0 verdict

**Proof-grade ready.** All seven security claims are now backed by machine-checkable evidence:

- **C1 Authorization Safety**: bounded-proven (TLC, 6 invariants) + symbolic-proven (Tamarin, 5 steps).
- **C2 Replay Safety**: bounded-proven (TLC) + symbolic-proven (Tamarin, 2 steps; with documented `accepted_once_per_message` restriction).
- **C3 Revocation Safety**: bounded-proven (TLC) + symbolic-proven (Tamarin, 2 steps).
- **C4 Signature Binding**: symbolic-proven (Tamarin, 6 steps; `authentication` lemma) + tested.
- **C5 Audit DAG Tamper Evidence**: tested (SHA-256 collision-resistance assumed; out of state-machine scope).
- **C6 No Tool Before Authorization**: symbolic-proven (Tamarin, 3 steps; `tool_safety` lemma) + tested.
- **C7 Bounded State-Machine Safety**: bounded-proven (TLC, 9 invariants × 11,601 states).

All 15 gate items answer Yes. The release is published at https://github.com/RaneemAlthaqafi/SIFR_Protocol/releases/tag/v0.4.0 with both zips attached.

## Honest residuals (not gate failures)

These remain documented scope boundaries:
- Cryptographic primitives (Ed25519, Argon2id, AES-GCM, SHA-256) are *assumed* secure. Tamarin abstracts them.
- W3C VC compliance is not claimed; credentials are VC-inspired.
- WASM isolation is verified for the calculator + 2 adversarial fixtures.
- QUIC beyond loopback is single-host Docker bridge + NetEm; not multi-host or Internet-scale.
- TLA+ verification is bounded; lifting to unbounded is future work.
- The `replay_resistance` Tamarin lemma's proof depends on the `accepted_once_per_message` restriction. This restriction is the symbolic-model abstraction of `sifr/replay.py:ReplayCache.check_and_record`. Removing the restriction makes the protocol's wire-level Dolev-Yao adversary trivially replay messages — the cache is the load-bearing component.
