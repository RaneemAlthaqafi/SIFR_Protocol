"""Replay protection: a per-(sender, session, message_id) cache with a sliding
timestamp window.

Reject conditions:
- Duplicate (sender_id, session_id, message_id) within the cache.
- Message timestamp older than `window_seconds` before now (stale).
- Message timestamp newer than `window_seconds` after now (clock-skew/forged).

The cache key intentionally uses `message_id` and NOT the signature value, so
re-signing the same message_id with a different signature is still rejected.

Optional persistence: SQLite at `store_path`.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .errors import ReplayError
from .utils import parse_utc

DEFAULT_WINDOW_SECONDS = 300  # 5 minutes

__all__ = ["ReplayCache", "DEFAULT_WINDOW_SECONDS"]


class ReplayCache:
    def __init__(
        self,
        *,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        store_path: Optional[Path | str] = None,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self._lock = threading.Lock()
        self._mem: dict[tuple[str, str, str], datetime] = {}
        self._db: Optional[sqlite3.Connection] = None
        if store_path is not None:
            self._open_db(Path(store_path))

    def _open_db(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False, timeout=10.0
        )
        # WAL mode lets multiple processes read while a writer commits.
        # busy_timeout coordinates concurrent INSERTs into the unique index.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS replay "
            "(sender TEXT, session TEXT, msgid TEXT, ts REAL, "
            "PRIMARY KEY(sender, session, msgid))"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_replay_ts ON replay(ts)")
        for sender, session, msgid, ts in self._db.execute(
            "SELECT sender, session, msgid, ts FROM replay"
        ):
            self._mem[(sender, session, msgid)] = datetime.fromtimestamp(ts, tz=timezone.utc)

    def check_and_record(self, message: dict[str, Any], *, now: Optional[datetime] = None) -> None:
        nowdt = now or datetime.now(timezone.utc)
        sender = message.get("sender_id")
        session = message.get("session_id")
        msgid = message.get("message_id")
        timestamp_str = message.get("timestamp")
        if not (sender and session and msgid and timestamp_str):
            raise ReplayError(
                "message missing sender_id/session_id/message_id/timestamp"
            )
        ts = parse_utc(timestamp_str)
        skew = (nowdt - ts).total_seconds()
        if skew > self.window.total_seconds():
            raise ReplayError(
                f"stale timestamp: {skew:.1f}s older than window {self.window.total_seconds():.0f}s"
            )
        if -skew > self.window.total_seconds():
            raise ReplayError(
                f"future timestamp: {-skew:.1f}s ahead of window {self.window.total_seconds():.0f}s"
            )

        key: tuple[str, str, str] = (sender, session, msgid)
        with self._lock:
            self._gc_locked(nowdt)
            if key in self._mem:
                raise ReplayError(f"duplicate message: {sender}/{session}/{msgid}")
            self._mem[key] = ts
            if self._db is not None:
                try:
                    self._db.execute(
                        "INSERT INTO replay (sender, session, msgid, ts) VALUES (?, ?, ?, ?)",
                        (sender, session, msgid, ts.timestamp()),
                    )
                except sqlite3.IntegrityError:
                    raise ReplayError(
                        f"duplicate message (db): {sender}/{session}/{msgid}"
                    )

    def _gc_locked(self, now: datetime) -> None:
        cutoff = now - self.window
        expired = [k for k, ts in self._mem.items() if ts < cutoff]
        for k in expired:
            del self._mem[k]
        if self._db is not None:
            self._db.execute("DELETE FROM replay WHERE ts < ?", (cutoff.timestamp(),))

    def __contains__(self, key: tuple[str, str, str]) -> bool:
        return key in self._mem

    def __len__(self) -> int:
        return len(self._mem)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
