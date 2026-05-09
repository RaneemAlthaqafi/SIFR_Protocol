# SIFR v0.3 QUIC Beyond-Loopback Evaluation

The v0.3 strict-evidence layer requires QUIC validation beyond `127.0.0.1` loopback. This document describes the Docker-Compose + NetEm pipeline and reports the measured numbers.

## Setup

Two containers (`sifr_quic_server`, `sifr_quic_client`) run from the same image (`sifr_quic_node:v0.3`, built from `docker/Dockerfile.quic_node`). They are connected by a Docker bridge network `docker_sifrnet`. Each container runs Python 3.11, `aioquic` 1.3.0, and the SIFR `sifr/` package mounted into `/app`.

Both containers receive `cap_add: NET_ADMIN` so the entrypoint can call `tc qdisc add dev eth0 root netem ...` to inject packet delay or loss before the QUIC handshake. The shape of NetEm impairment is controlled by environment variables:

- `SIFR_NETEM_DELAY_MS=20` — adds a 20 ms one-way delay on `eth0`.
- `SIFR_NETEM_LOSS_PCT=1` — drops 1% of packets uniformly.
- Both env vars unset — no impairment (container baseline).

The orchestration script `scripts/run_quic_network_bench.sh` builds the image, runs each configuration via `docker compose up --abort-on-container-exit`, captures the per-config CSV row written by the client, and assembles the result file at `benchmarks/results/v0.3/quic_network_latency.csv`.

## Workload

The client signs an Ed25519 SIFR `Thought` message, sends it over a QUIC stream, awaits an `ack` from the server, and records the wall-clock RTT. The server verifies the embedded test public key, appends the message to an audit DAG, and replies. This is the same `sign+verify+DAG` workload measured for the loopback baseline in `benchmarks/bench_quic_latency.py`.

## Results

Numbers below are from `benchmarks/results/v0.3/quic_network_latency.csv` produced on a Docker Desktop / WSL2 backend:

| Configuration | n | mean RTT (ms) | p95 RTT (ms) | Notes |
|---|---|---|---|---|
| `loopback_baseline` | 500 | 0.42 | n/a | seeded from `quic_latency.csv`; one process, both ends on `127.0.0.1` |
| `container_baseline` | 100 | 0.60 | 1.00 | two containers on Docker bridge, no impairment |
| `container_delay_20ms` | 100 | 22.03 | 22.77 | NetEm delay 20 ms on `eth0` (one-way) |
| `container_loss_1pct` | 100 | 0.98 | 1.19 | NetEm uniform 1% drop |
| `container_loss_5pct` | 60 | 2.48 | 31.87 | NetEm uniform 5% drop; p95 spikes from QUIC retransmits |

The container baseline costs ~0.18 ms over loopback — the full Docker bridge path (NAT, namespace, virtual ethernet) adds modest overhead. The 20 ms injected delay shows up as ~22 ms one-way RTT, consistent with NetEm applying delay on packets leaving `eth0` plus the round-trip baseline. 1% packet loss adds ~50% RTT (one or two retransmits per round-trip). 5% packet loss is the worst case in this evaluation: the mean stays low (most packets succeed quickly) but the p95 spikes 30× as QUIC's retransmit timer governs the worst offenders.

## What this is NOT

- **Not an Internet-scale evaluation.** Both containers run on the same host on a Docker bridge. There is no NAT traversal, no real router queueing, no MTU discovery, no real BBR/CUBIC vs network behaviour, no IPv6 mobility test.
- **Not a multi-host or geo-distributed test.** No two-machine, no WAN, no jitter / reordering / duplication / bandwidth limits beyond the simple delay+loss profiles above.
- **Not a security evaluation of QUIC itself.** The handshake uses self-signed RSA-2048 certificates with `verify=False` on the client side for measurement convenience.

## Reproduction

```bash
# Prerequisite: Docker daemon running.
bash scripts/run_quic_network_bench.sh
python scripts/generate_quic_network_figure.py
```

The figure is written to `paper/figures/benchmark_quic_network.png`. The raw CSV at `benchmarks/results/v0.3/quic_network_latency.csv` is committed; rerunning the pipeline regenerates it deterministically (within environmental variance of NetEm).

## v0.5 extended profile sweep (Docker Compose + NetEm)

The v0.5 harness adds:

- **Two-network compose**: `docker/compose_quic_two_networks.yml` puts the
  client and server on disjoint bridge networks joined by a "trunk" bridge.
  Impairment is applied on the client's trunk-facing `eth1`, not on the
  loopback or service network.
- **Six profiles**: baseline, delay20, delay100, loss1, loss5, jitter,
  bandwidth (10 Mbit/s TBF cap). Each profile is one entry in
  `benchmarks/bench_quic_network.PROFILES`.
- **Driver**: `python benchmarks/bench_quic_network.py --profiles ...`
  builds the image once, sweeps the profile list, captures per-profile
  CSVs from the client container, and writes a unified
  `benchmarks/results/quic_network_latency.csv` with columns
  `(profile, iteration, rtt_ms)` plus a metadata JSON next to it.

Run on a Docker-equipped Linux host:

```bash
python benchmarks/bench_quic_network.py \
  --profiles baseline delay20 delay100 loss1 loss5 jitter bandwidth \
  --n 200
```

### Honest non-claim

> The v0.5 sweep adds jitter and bandwidth profiles and uses a separate
> trunk network so impairment is applied between containers, not on
> loopback. It is **still single-host** emulation. SIFR does not claim
> Internet-scale, multi-host, multi-AZ, NAT-traversal, or mobile-network
> evaluation. Operators who want those should re-run the same workload
> against two real hosts (the same Python script and TLS cert work
> unchanged) and contribute results back.

### Environment requirements

- Linux host or WSL2 backend with `tc`/`iproute2` available inside
  containers (the SIFR Dockerfile installs it).
- Docker Compose v2 (`docker compose ...` form, not `docker-compose`).
- The benchmarking process needs to mount `docker/out/` from the client
  container; ensure your Docker bind-mount permissions allow this.

### Why the sweep is not in CI

Public CI runners typically do not grant `NET_ADMIN`, which is required by
NetEm. The harness is therefore documented as an *operator-driven*
benchmark, not a pre-merge gate. The repository commits the v0.3 numbers
so paper figures remain reproducible without Docker; v0.5's expanded
profiles are produced by the operator.
