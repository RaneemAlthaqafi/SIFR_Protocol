"""Benchmark DID resolution overhead: cold vs warm cache, did:sifr vs did:web."""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from sifr.crypto import generate_keypair, public_key_to_b64
from sifr.did.did_sifr import DidSifrResolver
from sifr.did.did_web import DidWebResolver

from did_web_server import DidWebFixture


def _make_doc(did: str, kid: str, pub_b64: str) -> dict:
    return {
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyBase64": pub_b64,
            }
        ],
    }


def bench_did_sifr(n: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _, pub = generate_keypair()
        did = "did:sifr:bench"
        kid = f"{did}#key-1"
        (root / "bench.json").write_text(
            json.dumps(_make_doc(did, kid, public_key_to_b64(pub))),
            encoding="utf-8",
        )

        t0 = time.perf_counter()
        for _ in range(n):
            r = DidSifrResolver(root)
            r.resolve(kid)
        cold = time.perf_counter() - t0

        warm_resolver = DidSifrResolver(root)
        warm_resolver.resolve(kid)
        t0 = time.perf_counter()
        for _ in range(n):
            warm_resolver.resolve(kid)
        warm = time.perf_counter() - t0

    return {
        "method": "did:sifr",
        "n": n,
        "cold_avg_ms": round(cold / n * 1000, 6),
        "warm_avg_ms": round(warm / n * 1000, 6),
    }


def bench_did_web(n: int) -> dict:
    with DidWebFixture() as fx:
        _, pub = generate_keypair()
        did = fx.did_for_path()
        kid = f"{did}#key-1"
        fx.serve_document("/.well-known/did.json", _make_doc(did, kid, public_key_to_b64(pub)))

        t0 = time.perf_counter()
        for _ in range(n):
            r = DidWebResolver(scheme="http")
            r.resolve(kid)
        cold = time.perf_counter() - t0

        warm_resolver = DidWebResolver(scheme="http")
        warm_resolver.resolve(kid)
        t0 = time.perf_counter()
        for _ in range(n):
            warm_resolver.resolve(kid)
        warm = time.perf_counter() - t0

    return {
        "method": "did:web",
        "n": n,
        "cold_avg_ms": round(cold / n * 1000, 6),
        "warm_avg_ms": round(warm / n * 1000, 6),
    }


def main() -> None:
    out = REPO_ROOT / "benchmarks" / "results" / "did_resolution.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        bench_did_sifr(1000),
        bench_did_sifr(5000),
        bench_did_web(200),
        bench_did_web(500),
    ]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {out}")
    for r in rows:
        print(
            f"  {r['method']:10} n={r['n']:>5}  "
            f"cold={r['cold_avg_ms']:.4f} ms  warm={r['warm_avg_ms']:.4f} ms"
        )


if __name__ == "__main__":
    main()
