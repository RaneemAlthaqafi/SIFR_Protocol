# Revocation and Replay Scope

## Honest claim

> SIFR supports process-shared replay protection and capability revocation
> through a durable SQLite-backed verifier state and a signed JSONL
> revocation log. Both surfaces re-verify integrity at load time and across
> processes, but SIFR does **not** implement Byzantine consensus or global
> revocation propagation between independent verifier deployments.

## Replay protection

`sifr.replay.ReplayCache` keys on `(sender_id, session_id, message_id)` and
holds entries for `window_seconds` (default 300 s).

Process-shared design:

- Persistence layer is SQLite, opened per-process in WAL mode with a
  busy-timeout of 5 s.
- The `(sender, session, msgid)` PRIMARY KEY makes duplicate INSERTs
  impossible across any number of processes — the loser's commit raises
  `sqlite3.IntegrityError`, which the cache surfaces as `ReplayError`.
- WAL journaling lets readers and a single writer make progress without
  blocking each other.
- Each process keeps its own in-memory snapshot for fast positive-hit
  detection. Snapshots can lag, but the SQLite UNIQUE constraint is the
  authoritative gate.

Restart durability:

- The cache loads all rows at construction time; a verifier restarted
  with the same `store_path` re-observes prior entries.
- A timestamp-based GC (`_gc_locked`) deletes rows older than the sliding
  window during writes.

What this is NOT:

- It is not a global ordering. Two processes that record different keys
  concurrently are not linearized; they are independent.
- It is not coordination across deployments. Two SIFR clusters with
  separate replay databases will not detect cross-cluster replay.
- It is not Byzantine. A malicious writer that holds the SQLite file can
  insert arbitrary rows — but the rows alone do not authorize anything;
  every authorization still requires a valid signed message.

Tests:

| File | Property |
|---|---|
| `tests/test_distributed_replay.py::test_replay_rejected_across_processes` | Process A records → Process B rejects. |
| `tests/test_distributed_replay.py::test_replay_persists_across_restart` | New cache instance with same store_path still rejects an old key. |
| `tests/test_distributed_replay.py::test_replay_does_not_collide_across_distinct_keys` | Negative control on the keying. |
| `tests/test_distributed_replay.py::test_concurrent_same_message_only_one_accepts` | Four-way race: exactly one ACCEPT. |
| `tests/test_replay.py` (existing) | Window-edge, missing-field, in-process duplicate, etc. |

## Capability revocation

`sifr.revocation.RevocationRegistry` maintains a JSONL append-only log of
signed `CapabilityRevocation` messages.

Process-shared design:

- Append-only JSONL file, line per revocation. The line is the full signed
  SIFR message (canonical-JSON, sorted keys, default separators).
- Every load (`_load`) re-verifies the signature on every line via
  `verify_message`, against the configured `verifier_key`. A line that
  fails verification is rejected — the registry refuses to start with a
  tampered log.
- New `RevocationRegistry.reload()` re-reads the file into the in-memory
  map, so a long-lived verifier can pick up new revocations written by a
  separate writer process without restarting.

What this is NOT:

- It is not a consensus log. There is no leader, no quorum, no global
  ordering across deployments. Two writers that both append entries do
  not coordinate, but the file is append-only so both entries survive.
- It is not eventual consistency in any formal sense. A reader that has
  never called `reload()` will not observe new entries until it does so
  explicitly.
- It is not multicast. Distributing revocations across hosts is left to
  the operator (rsync, NFS, S3-with-versioning, …); SIFR validates the
  signed lines wherever they end up.

Tests:

| File | Property |
|---|---|
| `tests/test_distributed_revocation.py::test_revocation_visible_across_processes_after_reload` | Process A revokes → Process B reads the file and observes the revocation. |
| `tests/test_distributed_revocation.py::test_revocation_reload_picks_up_new_entries` | Long-lived verifier sees new entries via `reload()`. |
| `tests/test_distributed_revocation.py::test_tampered_revocation_log_rejected_on_load` | Mutating a line's payload fails signature verification at load. |
| `tests/test_distributed_revocation.py::test_revocation_registry_rejects_wrong_type_entry` | A non-`CapabilityRevocation` line is rejected. |
| `tests/test_revocation.py` (existing) | Sign-and-verify cycle, double-revoke idempotence, etc. |

## What we explicitly do NOT claim

- Byzantine consensus.
- Global replay-cache or revocation-list propagation across independent
  deployments.
- Liveness under network partition.
- Total ordering of revocations.
- Anything CAP-theorem-strong about JSONL plus rsync.

These are intentionally future work. The narrowed claim in this document
is durable, integrity-checked, multi-process verification within a shared
file system.
