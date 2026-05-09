# SIFR v0.3.1 Strict Quality Gate

Honest yes/no answers per the v0.3 strict obligations. Each row records the **command** and the **observed output** so a reviewer can rerun every check from a clean clone.

| # | Item | Answer | Command and observed output |
|---|---|---|---|
| 1 | Clean git status from a fresh clone? | **Yes** | `git status -sb` → `## main...origin/main` (no modifications, no untracked files except gitignored zips). |
| 2 | All tests pass? | **Yes** | `SIFR_TLC_FROZEN=1 python -m pytest -q` → `170 passed in 10.49s`. |
| 3 | All demos pass? | **Yes** | Every demo in `examples/demo_*.py` exits 0 individually. The integration demo prints all 11 spec'd `OK` lines including `Formal model artifacts: PRESENT`. |
| 4 | All benchmarks regenerate? | **Yes** | `SIFR_BENCH_VERSION=v0.3 bash scripts/run_all_benchmarks.sh` writes 8 result files into `benchmarks/results/v0.3/` plus `manifest.json` with per-file SHA-256. |
| 5 | All figures regenerate? | **Yes** | `python scripts/generate_all_figures.py` writes 9 PNGs + 1 PDF + `paper/figures/figure_manifest.json`. |
| 6 | TLC model check rerun? | **Yes** | `bash formal/run_tlc.sh` produces a fresh `formal/output/tlc_output.txt` with `11,601 distinct states found`, `Model checking completed. No error has been found.` |
| 7 | TLC output fresh? | **Yes** | `python scripts/refresh_formal_metadata.py` regenerates `tlc_metadata.json` + `model_hashes.json`. `tests/test_formal_artifacts.py::test_model_hashes_match_files` asserts hash agreement; `SIFR_TLC_FROZEN=1` makes it fail-closed. |
| 8 | Artifact zip rebuilt? | **Yes** | `SIFR_RELEASE_VERSION=v0.3.1 python scripts/build_release_zips.py` → `sifr-v0.3.1-research-artifact.zip` (193 files, 1,291,433 bytes). SHA-256 in `review/v0_3_release_manifest.json`. |
| 9 | Overleaf zip rebuilt? | **Yes** | Same script → `sifr-v0.3.1-overleaf-ready.zip` (23 files, 1,097,344 bytes). |
| 10 | Proof obligations complete? | **Yes** | [docs/proof_obligations_v0_3.md](../docs/proof_obligations_v0_3.md) — 11 proven, 3 partial (VC-inspired vs W3C VC, no DID multibase/JWK, WASM scope). The 3 partials are documented scope choices, not missing evidence. |
| 11 | Paper claims mapped to evidence? | **Yes** | `paper/main.tex` has `\section{Claims and Evidence Map (v0.3)}` with 14-row table. Abstract reports v0.3 numbers (30 attacks, 9 invariants, 11,601 states, loopback + Docker+NetEm). v0.2 historical mentions are clearly labeled. |
| 12 | QUIC evaluated beyond loopback? | **Yes** | `bash scripts/run_quic_network_bench.sh` runs Docker-Compose + NetEm across 5 configs. Output at `benchmarks/results/v0.3/quic_network_latency.csv`; figure at `paper/figures/benchmark_quic_network.png`; methodology at [docs/quic_network_evaluation.md](../docs/quic_network_evaluation.md). |
| 13 | DID supported formats documented? | **Yes** | [docs/did_method.md](../docs/did_method.md): `Ed25519VerificationKey2020`/`2018` with `publicKeyBase64`. Other formats explicitly out of scope. |
| 14 | Credential compliance scope exact? | **Yes** | Three places — paper Limitations, [docs/credential_model.md](../docs/credential_model.md), `sifr/credentials.py` docstring — all say "VC-inspired, not W3C VC compliant". |
| 15 | WASM scope exact? | **Yes** | [docs/wasm_sandbox.md](../docs/wasm_sandbox.md) and paper Limitations: "tested for the calculator and two adversarial fixtures only". |
| 16 | No production-security overclaim? | **Yes** | Paper Limitations: "no production-deployment readiness." |
| 17 | No W3C VC overclaim? | **Yes** | Confirmed at three locations (paper, doc, code). |
| 18 | No cryptographic-proof overclaim? | **Yes** | Paper: "bounded safety, not a cryptographic proof, liveness proof, or refinement proof." [docs/formal_model.md](../docs/formal_model.md) repeats. |
| 19 | No arbitrary-code sandbox overclaim? | **Yes** | Paper and `docs/wasm_sandbox.md` qualify the claim to the calculator + adversarial fixtures. |
| 20 | No stale result files? | **Yes** | `benchmarks/results/{v0.1,v0.2,v0.3}/` versioned. Top-level v0.1-named files in `.gitignore`. `paper/figures/figure_manifest.json` records source-data hashes; mismatches surface stale figures. |

## Tally

| Verdict | Count | Items |
|---|---|---|
| Yes | 20 | all |
| Partial | 0 | — |
| No | 0 | — |

## Reproduction transcript (Linux / WSL)

```
$ git clone https://github.com/RaneemAlthaqafi/SIFR_Protocol.git sifr-v031-audit
$ cd sifr-v031-audit
$ git checkout v0.3.1
$ python -m venv .venv && source .venv/bin/activate
$ pip install -e ".[dev]"
$ SIFR_TLC_FROZEN=1 python -m pytest -q
....................................................................... [ 42%]
....................................................................... [ 84%]
.........................                                               [100%]
170 passed
$ python examples/demo_secure_quic_wasm_did_flow.py
=== SIFR v0.2 Secure Flow Demo ===
DID resolution: OK
QUIC session: OK
Hello signature: OK
Capability credential: OK
Replay check: OK
Revocation check: OK
Action authorized: OK
WASM calculator executed: OK
Observation verified: OK
Audit DAG integrity: OK
Formal model artifacts: PRESENT
Result: 5
Demo completed successfully.
$ python examples/demo_v0_3_adversary_cases.py
=== SIFR v0.3 Strict Adversary Cases (30 attacks) ===
30 passed
All 30 v0.3 attacks were correctly rejected.
```

## Reproduction transcript (Windows PowerShell)

```
> python -m venv .venv
> .\.venv\Scripts\Activate.ps1
> pip install -e ".[dev]"
> $env:SIFR_TLC_FROZEN="1"
> python -m pytest -q
170 passed
> powershell -ExecutionPolicy Bypass -File scripts\reproduce_all.ps1
```

## Honest residuals (non-blocking)

These are documented scope choices, not gate failures:
- Credentials remain VC-inspired (no JSON-LD / URDNA2015) — paper, doc, code agree.
- DID resolution supports `Ed25519VerificationKey2020/2018` + `publicKeyBase64` only — others explicitly out of scope.
- WASM isolation is verified for the calculator + 2 adversarial fixtures — not arbitrary-untrusted-code safety.
- QUIC beyond-loopback is "single-host Docker bridge + NetEm" — not multi-host or Internet-scale.
