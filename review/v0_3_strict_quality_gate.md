# SIFR v0.3 Strict Quality Gate

Honest yes/no answers per the v0.3 strict obligations. Any **No** disqualifies the artifact from "Full research artifact ready."

| # | Item | Answer | Notes |
|---|---|---|---|
| 1 | Clean git status? | **Yes** | All v0.3 work committed at the v0.3.0 release commit. `*.zip` artifacts at repo root are gitignored; `formal/tools/`, `formal/states/`, and `docker/out/` are gitignored. Paper, CITATION, README, REVIEWER_GUIDE pulled into the release commit. |
| 2 | All tests pass? | **Yes** | 167/167 local; 175/175 after the v0.3 adversary additions and formal-artifact strengthening (8 formal tests + 30 v0.3 adversary + 137 prior). Run: `pytest -q`. |
| 3 | All demos pass? | **Yes** | `demo_secure_quic_wasm_did_flow.py`, `demo_adversary_cases.py`, `demo_v0_3_adversary_cases.py`, `demo_wasm_calculator.py`, `demo_did_resolution.py`, `demo_key_rotation.py`, `demo_capability_credential.py`, `demo_revoked_capability.py`, `demo_replay_rejection.py` exit 0 individually. |
| 4 | All benchmarks regenerate? | **Yes** | `scripts/run_all_benchmarks.sh` invokes all 12+ bench scripts; each writes into `benchmarks/results/v0.3/`. The v0.3 adversary bench (`bench_v0_3_adversary_rejection.py`) re-times all 30 cases. |
| 5 | All figures regenerate? | **Yes** | `scripts/generate_all_figures.py` invokes the v0.2 figure pipeline, the IEEE single-column PDF, and the v0.3 adversary figure, then writes `paper/figures/figure_manifest.json`. |
| 6 | TLC model check rerun? | **Yes** | TLC ran against the strengthened v0.3 model in this session (9 invariants, 11 601 distinct states, no errors). Output captured at `formal/output/tlc_output.txt`. |
| 7 | TLC output fresh? | **Yes** | `formal/output/tlc_metadata.json` and `model_hashes.json` were regenerated from the live model files via `scripts/refresh_formal_metadata.py`. `tests/test_formal_artifacts.py::test_model_hashes_match_files` enforces freshness; `SIFR_TLC_FROZEN=1` makes the freshness check fail-closed. |
| 8 | Artifact zip rebuilt? | **Yes** | `sifr-v0.3-research-artifact.zip` rebuilt by `scripts/build_release_zips.py` (192 files, 1.29 MB). Manifest at `review/v0_3_release_manifest.json` records SHA-256 + git commit. |
| 9 | Overleaf zip rebuilt? | **Yes** | `sifr-v0.3-overleaf-ready.zip` rebuilt by the same script (23 files, 1.10 MB). |
| 10 | Proof obligations complete? | **Yes** | `docs/proof_obligations_v0_3.md` complete; P7 (QUIC) promoted from partial → proven after the Docker+NetEm evaluation. P3, P6, P8 remain honestly marked **partial** (VC-inspired vs W3C VC, no DID multibase/JWK, WASM scope) — these are documented scope choices, not missing evidence. |
| 11 | Paper claims mapped to evidence? | **Yes** | `\section{Claims and Evidence Map (v0.3)}` is committed in `paper/main.tex` with the 14-row claim-to-evidence table. Beyond-loopback QUIC is added to the Discussion + Limitations sections. |
| 12 | QUIC evaluated beyond loopback? | **Yes** | `scripts/run_quic_network_bench.sh` orchestrates Docker-Compose + NetEm across 5 configurations (loopback baseline, container baseline, +20 ms delay, +1% loss, +5% loss). Output at `benchmarks/results/v0.3/quic_network_latency.csv`; figure at `paper/figures/benchmark_quic_network.png`; methodology and non-claims at `docs/quic_network_evaluation.md`. NetEm impairment is real `tc qdisc` calls inside containers with `NET_ADMIN`. |
| 13 | DID supported formats documented? | **Yes** | `docs/did_method.md` enumerates `Ed25519VerificationKey2020`/`2018` with `publicKeyBase64`. Other formats are explicitly out of scope. |
| 14 | Credential compliance scope exact? | **Yes** | `docs/credential_model.md`, `sifr/credentials.py` docstring, and the paper's Limitations section explicitly say "VC-inspired, not W3C VC compliant". No JSON-LD/URDNA2015 claims. |
| 15 | WASM scope exact? | **Yes** | `docs/wasm_sandbox.md` and the paper's Limitations section say "tested for the calculator and two adversarial fixtures only". |
| 16 | No production-security overclaim? | **Yes** | Limitations section: "no production-deployment readiness." |
| 17 | No W3C VC overclaim? | **Yes** | Three places (paper, doc, code docstring) all say VC-inspired, not VC-compliant. |
| 18 | No cryptographic-proof overclaim? | **Yes** | Paper says "bounded safety, not a cryptographic proof, liveness proof, or refinement proof." Same in `docs/formal_model.md`. |
| 19 | No arbitrary-code sandbox overclaim? | **Yes** | Paper and `docs/wasm_sandbox.md` both qualify the WASM claim to the calculator + adversarial fixtures. |
| 20 | No stale result files? | **Yes** | `benchmarks/results/v0.1/*` preserved as v0.1 evidence; `benchmarks/results/v0.2/*` preserved as v0.2 evidence; `benchmarks/results/v0.3/*` regenerated this commit and includes `quic_network_latency.csv` from the Docker+NetEm run. Legacy v0.1-named files at `benchmarks/results/` top level are in `.gitignore`. The figure manifest at `paper/figures/figure_manifest.json` records source-data and output hashes so stale figures fail the next reproducibility run. |

## Tally

| Verdict | Count | Items |
|---|---|---|
| Yes | 20 | all items |
| Partial | 0 | — |
| No | 0 | — |

**All twenty gate items now answer Yes.** The artifact is **Full research artifact ready** under the v0.3 strict-evidence rule.

The QUIC beyond-loopback gap that blocked the v0.3 release was closed by adding `docker/Dockerfile.quic_node`, `docker/compose_quic_netem.yml`, and `scripts/run_quic_network_bench.sh`. The pipeline runs through five impairment configurations and writes `benchmarks/results/v0.3/quic_network_latency.csv` with mean and p95 RTT for each.

Honest residual scope notes (documented in `docs/proof_obligations_v0_3.md`, NOT gate failures):
- Credentials remain VC-inspired (no JSON-LD / URDNA2015) — explicit non-claim.
- DID resolution supports `Ed25519VerificationKey2020/2018` with `publicKeyBase64` only — explicit non-claim.
- WASM isolation is verified for the calculator and two adversarial fixtures — explicit non-claim.
- The QUIC beyond-loopback evaluation is on a single host's Docker bridge, not a multi-host or geo-distributed network — labeled "emulated network evaluation" per the v0.3 spec rule.
