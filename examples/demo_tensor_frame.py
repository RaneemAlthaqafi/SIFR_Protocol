import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.tensor import create_tensor_payload, random_vector, tensor_payload_to_array

if __name__ == "__main__":
    vec = random_vector()
    payload = create_tensor_payload(vec)
    decoded = tensor_payload_to_array(payload)
    print(f"TensorFrame {payload['tensor_id']} shape={decoded.shape} dtype={decoded.dtype}")
