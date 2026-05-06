import numpy as np
import pytest

from sifr.tensor import create_tensor_payload, random_vector, tensor_payload_to_array


def test_tensorframe_creates_and_roundtrips():
    vec = random_vector()
    payload = create_tensor_payload(vec)
    decoded = tensor_payload_to_array(payload)
    assert decoded.shape == (384,)
    assert decoded.dtype == np.float32
    assert np.allclose(vec, decoded)


def test_shape_validates():
    payload = create_tensor_payload(random_vector())
    payload["shape"] = [383]
    with pytest.raises(ValueError):
        tensor_payload_to_array(payload)


def test_dtype_validates():
    payload = create_tensor_payload(random_vector())
    payload["dtype"] = "float64"
    with pytest.raises(ValueError):
        tensor_payload_to_array(payload)


def test_base64_encoding_present():
    payload = create_tensor_payload(random_vector())
    assert payload["encoding"] == "base64"
    assert isinstance(payload["data"], str)
