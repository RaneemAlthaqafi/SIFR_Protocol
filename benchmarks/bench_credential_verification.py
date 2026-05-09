"""Benchmark VC-inspired credential issue + verify latency."""
from __future__ import annotations

import csv
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_io import versioned_results_dir

from sifr.credentials import issue_credential, verify_credential
from sifr.crypto import generate_keypair
from sifr.utils import utc_now_iso


def _grant_payload(issuer: str, subject: str, expires: str) -> dict:
    return {
        "capability_id": "cap_001",
        "issuer": issuer,
        "subject": subject,
        "actions": ["tool.calculator.add"],
        "resource_scope": ["calculator"],
        "issued_at": utc_now_iso(),
        "expires_at": expires,
        "budget": {"max_calls": 5, "max_payload_bytes": 1024},
        "constraints": {"allow_delegation": False},
    }


def bench(n: int) -> dict:
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    subject = "did:sifr:bob"
    kid = f"{issuer}#key-1"
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    payload = _grant_payload(issuer, subject, expires)

    t0 = time.perf_counter()
    creds = [
        issue_credential(
            issuer=issuer,
            subject=subject,
            capability_grant_payload=payload,
            issuer_private_key=priv,
            issuer_kid=kid,
            expires_at=expires,
        )
        for _ in range(n)
    ]
    issue_total = time.perf_counter() - t0

    t0 = time.perf_counter()
    for cred in creds:
        verify_credential(cred, pub)
    verify_total = time.perf_counter() - t0

    return {
        "n": n,
        "avg_issue_ms": round(issue_total / n * 1000, 4),
        "avg_verify_ms": round(verify_total / n * 1000, 4),
    }


def main() -> None:
    out = versioned_results_dir() / "credential_verification.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [bench(1000), bench(5000)]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {out}")
    for r in rows:
        print(f"  n={r['n']:>5}  issue={r['avg_issue_ms']:.4f} ms  verify={r['avg_verify_ms']:.4f} ms")


if __name__ == "__main__":
    main()
