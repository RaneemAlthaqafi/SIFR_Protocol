"""Multi-process replay-cache tests.

These tests prove the v0.5 claim:

> SIFR supports process-shared replay through a durable SQLite-backed
> verifier state.

The mechanism is the `PRIMARY KEY(sender, session, msgid)` constraint plus
WAL journaling: when process B INSERTs the same key process A already
recorded, SQLite raises an IntegrityError which the cache surfaces as
ReplayError. Tests exercise both directions and the restart-durability
path.
"""
from __future__ import annotations

import multiprocessing
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from sifr.replay import ReplayCache
from sifr.errors import ReplayError
from sifr.utils import utc_now_iso


REPO_ROOT = Path(__file__).resolve().parent.parent


def _msg(*, sender="did:sifr:alice", session="sess1", msgid="m1", ts=None):
    return {
        "sender_id": sender,
        "session_id": session,
        "message_id": msgid,
        "timestamp": ts or utc_now_iso(),
    }


def _spawn_python(code: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run `python -c <code>` in a fresh subprocess.

    A fresh interpreter guarantees process-level isolation of the cache.
    Output is captured so the test can assert on it.
    """
    full_env = os.environ.copy()
    full_env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + full_env.get("PYTHONPATH", "")
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=full_env,
        cwd=str(cwd or REPO_ROOT),
        timeout=60,
    )


def test_replay_rejected_across_processes(tmp_path):
    """Process A records a message; process B (separate interpreter) replays it."""
    store = tmp_path / "replay.sqlite"
    msg = _msg(msgid="multi-proc-1")

    # Process A: write the entry.
    a_code = textwrap.dedent(
        f"""
        import json, sys
        from sifr.replay import ReplayCache
        cache = ReplayCache(store_path=r"{store}")
        cache.check_and_record({msg!r})
        cache.close()
        print("A_OK")
        """
    )
    res_a = _spawn_python(a_code)
    assert "A_OK" in res_a.stdout, f"process A failed: {res_a.stderr}"

    # Process B: try the same message — must be rejected.
    b_code = textwrap.dedent(
        f"""
        import sys
        from sifr.replay import ReplayCache
        from sifr.errors import ReplayError
        cache = ReplayCache(store_path=r"{store}")
        try:
            cache.check_and_record({msg!r})
            print("B_NO_REJECT")
            sys.exit(1)
        except ReplayError as exc:
            print("B_REJECTED")
        cache.close()
        """
    )
    res_b = _spawn_python(b_code)
    assert "B_REJECTED" in res_b.stdout, (
        f"process B did not reject replay. stdout={res_b.stdout!r} stderr={res_b.stderr!r}"
    )


def test_replay_persists_across_restart(tmp_path):
    """A cache restarted with the same store_path still rejects an old message."""
    store = tmp_path / "replay-restart.sqlite"
    msg = _msg(msgid="restart-msg")

    cache_one = ReplayCache(store_path=store)
    cache_one.check_and_record(msg)
    cache_one.close()

    # Brand-new instance, same file.
    cache_two = ReplayCache(store_path=store)
    with pytest.raises(ReplayError, match="duplicate"):
        cache_two.check_and_record(msg)
    cache_two.close()


def test_replay_does_not_collide_across_distinct_keys(tmp_path):
    """Negative control: changing any of (sender, session, msgid) is a different key."""
    store = tmp_path / "distinct.sqlite"
    cache = ReplayCache(store_path=store)
    cache.check_and_record(_msg(sender="did:sifr:alice", msgid="x"))
    cache.check_and_record(_msg(sender="did:sifr:bob", msgid="x"))  # different sender
    cache.check_and_record(_msg(sender="did:sifr:alice", msgid="y"))  # different msgid
    cache.check_and_record(_msg(sender="did:sifr:alice", msgid="x", session="sess2"))  # diff session
    cache.close()


# Top-level worker functions for multiprocessing.Process — Windows requires
# spawn-mode workers to be picklable, so they cannot be local closures.

def _worker_record_only(store_path: str, msgid: str, result_queue) -> None:
    from sifr.replay import ReplayCache
    from sifr.errors import ReplayError
    cache = ReplayCache(store_path=store_path)
    try:
        cache.check_and_record(_msg(msgid=msgid))
        result_queue.put("ACCEPT")
    except ReplayError as exc:
        result_queue.put(f"REJECT:{exc}")
    finally:
        cache.close()


def test_concurrent_same_message_only_one_accepts(tmp_path):
    """Two processes racing to INSERT the same key: at most one accepts.

    SQLite's PRIMARY KEY constraint serializes the writes; the loser sees
    IntegrityError and the cache surfaces ReplayError. This is bounded by
    SQLite semantics, not by SIFR's own locks.
    """
    store = tmp_path / "race.sqlite"
    # Pre-create the DB to avoid the WAL-mode init race.
    ReplayCache(store_path=store).close()

    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue()
    procs = [
        ctx.Process(target=_worker_record_only, args=(str(store), "race-id", q))
        for _ in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0, f"worker exited with code {p.exitcode}"

    results = [q.get(timeout=5) for _ in range(4)]
    accepts = [r for r in results if r == "ACCEPT"]
    rejects = [r for r in results if r.startswith("REJECT")]
    assert len(accepts) == 1, (
        f"exactly one process should accept; got {len(accepts)}. results={results}"
    )
    assert len(rejects) == 3, f"three should reject; got results={results}"
