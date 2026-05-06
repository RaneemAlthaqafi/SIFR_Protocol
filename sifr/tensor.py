from __future__ import annotations

import base64
import json
from typing import Any

import numpy as np

SUPPORTED_DTYPES = {"float32": np.float32}


def random_vector(size: int = 384, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(size=size).astype(np.float32)


def encode_json_list(array: np.ndarray) -> list[float]:
    return array.astype(np.float32).tolist()


def encode_base64(array: np.ndarray) -> str:
    contiguous = np.ascontiguousarray(array.astype(np.float32))
    return base64.b64encode(contiguous.tobytes()).decode("ascii")


def decode_base64(data: str, shape: list[int], dtype: str) -> np.ndarray:
    if dtype not in SUPPORTED_DTYPES:
        raise ValueError("unsupported dtype")
    raw = base64.b64decode(data)
    arr = np.frombuffer(raw, dtype=SUPPORTED_DTYPES[dtype])
    expected = int(np.prod(shape))
    if arr.size != expected:
        raise ValueError("shape does not match payload length")
    return arr.reshape(shape)


def create_tensor_payload(array: np.ndarray, tensor_id: str = "emb_001") -> dict[str, Any]:
    if array.dtype != np.float32:
        array = array.astype(np.float32)
    return {
        "tensor_id": tensor_id,
        "dtype": "float32",
        "shape": list(array.shape),
        "encoding": "base64",
        "model_hint": "demo-random-embedding",
        "data": encode_base64(array),
        "privacy": {"dp_noise": False, "epsilon": None},
    }


def tensor_payload_to_array(payload: dict[str, Any]) -> np.ndarray:
    if payload.get("encoding") != "base64":
        raise ValueError("only base64 encoding is implemented")
    return decode_base64(payload["data"], payload["shape"], payload["dtype"])


def payload_size_bytes(obj: Any) -> int:
    return len(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))
