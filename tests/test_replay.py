from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sifr.errors import ReplayError
from sifr.replay import ReplayCache
from sifr.utils import utc_now_iso


def _msg(sender="did:sifr:alice", session="sess_1", msgid="msg_1", ts=None):
    return {
        "sender_id": sender,
        "session_id": session,
        "message_id": msgid,
        "timestamp": ts or utc_now_iso(),
    }


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def test_first_message_accepted():
    cache = ReplayCache()
    cache.check_and_record(_msg())
    assert len(cache) == 1


def test_duplicate_rejected():
    cache = ReplayCache()
    m = _msg()
    cache.check_and_record(m)
    with pytest.raises(ReplayError, match="duplicate"):
        cache.check_and_record(m)


def test_modified_signature_same_msgid_still_rejected():
    cache = ReplayCache()
    m1 = _msg()
    m1["signature"] = {"alg": "Ed25519", "kid": "x", "value": "AAAA"}
    cache.check_and_record(m1)
    m2 = dict(m1)
    m2["signature"] = {"alg": "Ed25519", "kid": "x", "value": "BBBB"}
    with pytest.raises(ReplayError, match="duplicate"):
        cache.check_and_record(m2)


def test_different_session_same_msgid_allowed():
    cache = ReplayCache()
    cache.check_and_record(_msg(session="sess_a"))
    cache.check_and_record(_msg(session="sess_b"))
    assert len(cache) == 2


def test_different_sender_same_msgid_allowed():
    cache = ReplayCache()
    cache.check_and_record(_msg(sender="did:sifr:a"))
    cache.check_and_record(_msg(sender="did:sifr:b"))
    assert len(cache) == 2


def test_stale_timestamp_rejected():
    cache = ReplayCache(window_seconds=60)
    old = datetime.now(timezone.utc) - timedelta(seconds=120)
    with pytest.raises(ReplayError, match="stale"):
        cache.check_and_record(_msg(ts=_iso(old)))


def test_future_timestamp_rejected():
    cache = ReplayCache(window_seconds=60)
    future = datetime.now(timezone.utc) + timedelta(seconds=120)
    with pytest.raises(ReplayError, match="future"):
        cache.check_and_record(_msg(ts=_iso(future)))


def test_within_window_accepted():
    cache = ReplayCache(window_seconds=60)
    inside = datetime.now(timezone.utc) - timedelta(seconds=30)
    cache.check_and_record(_msg(ts=_iso(inside)))


def test_missing_fields_rejected():
    cache = ReplayCache()
    with pytest.raises(ReplayError, match="missing"):
        cache.check_and_record({"sender_id": "x"})


def test_persistent_across_restart(tmp_path):
    db = tmp_path / "replay.sqlite"
    cache1 = ReplayCache(store_path=db)
    cache1.check_and_record(_msg())
    cache1.close()

    cache2 = ReplayCache(store_path=db)
    with pytest.raises(ReplayError, match="duplicate"):
        cache2.check_and_record(_msg())
    cache2.close()


def test_gc_releases_old_entries_with_explicit_now():
    cache = ReplayCache(window_seconds=60)
    t0 = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
    cache.check_and_record(_msg(msgid="msg_1", ts=_iso(t0)), now=t0)
    assert len(cache) == 1

    t1 = t0 + timedelta(seconds=90)
    cache.check_and_record(_msg(msgid="msg_2", ts=_iso(t1)), now=t1)
    assert ("did:sifr:alice", "sess_1", "msg_1") not in cache
    assert ("did:sifr:alice", "sess_1", "msg_2") in cache


def test_window_boundary_inclusive():
    """A message exactly at the boundary should still be acceptable."""
    cache = ReplayCache(window_seconds=60)
    t_now = datetime.now(timezone.utc)
    edge = t_now - timedelta(seconds=60)
    cache.check_and_record(_msg(ts=_iso(edge)), now=t_now)
