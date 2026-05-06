from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.crypto import generate_keypair, sign_message
from sifr.messages import create_message
from sifr.tensor import create_tensor_payload, encode_json_list, payload_size_bytes, random_vector


def main() -> None:
    out = Path("benchmarks/results/payload_size.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    priv, _ = generate_keypair()
    plain = {"action": "tool.calculator.add", "args": {"a": 2, "b": 3}}
    unsigned = create_message("Action", "did:sifr:a", "did:sifr:b", plain, session_id="s", message_id="m", timestamp="2026-01-01T00:00:00Z")
    signed = sign_message(unsigned, priv)
    vec = random_vector()
    tensor_json = {"tensor_id": "emb_001", "dtype": "float32", "shape": [384], "encoding": "json-list", "data": encode_json_list(vec)}
    tensor_b64 = create_tensor_payload(vec)
    rows = [
        ("plain_json_action", payload_size_bytes(plain)),
        ("sifr_unsigned_action", payload_size_bytes(unsigned)),
        ("sifr_signed_action", payload_size_bytes(signed)),
        ("tensor_json_list", payload_size_bytes(tensor_json)),
        ("tensor_base64_binary", payload_size_bytes(tensor_b64)),
    ]
    baseline = rows[0][1]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["case", "bytes", "overhead_vs_plain"])
        writer.writeheader()
        for case, size in rows:
            writer.writerow({"case": case, "bytes": size, "overhead_vs_plain": round(size / baseline, 4)})
    print(out)


if __name__ == "__main__":
    main()
