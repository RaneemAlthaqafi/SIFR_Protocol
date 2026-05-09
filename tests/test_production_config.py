from __future__ import annotations

import json
from datetime import timedelta

import pytest

from sifr.config import ConfigError, DeploymentMode, RateLimitConfig, SIFRConfig


def test_production_mode_rejects_demo_keys() -> None:
    cfg = SIFRConfig(
        mode=DeploymentMode.SINGLE_VERIFIER,
        key_store_uri="file:///secure/sifr-keystore.json",
        allow_demo_keys=True,
        demo_key_ids=("did:sifr:demo#key-1",),
    )
    with pytest.raises(ConfigError, match="demo keys are forbidden"):
        cfg.validate()


def test_production_mode_rejects_demo_key_store_uri() -> None:
    cfg = SIFRConfig(
        mode=DeploymentMode.SINGLE_VERIFIER,
        key_store_uri="demo://insecure-fixture-keys",
    )
    with pytest.raises(ConfigError, match="must not reference demo keys"):
        cfg.validate()


def test_required_config_missing_fails_closed() -> None:
    cfg = SIFRConfig(mode=DeploymentMode.SINGLE_VERIFIER)
    with pytest.raises(ConfigError, match="SIFR_KEY_STORE_URI"):
        cfg.validate()


def test_clustered_mode_requires_shared_state_configuration() -> None:
    cfg = SIFRConfig(
        mode=DeploymentMode.CLUSTERED_VERIFIER,
        key_store_uri="file:///secure/sifr-keystore.json",
    )
    with pytest.raises(ConfigError, match="durable replay_store_uri"):
        cfg.validate()


def test_payload_limit_enforced() -> None:
    cfg = SIFRConfig(
        mode=DeploymentMode.SINGLE_VERIFIER,
        key_store_uri="file:///secure/sifr-keystore.json",
        max_payload_bytes=16,
    )
    cfg.validate()
    cfg.enforce_payload_limit(b"1234567890abcdef")
    with pytest.raises(ConfigError, match="exceeds configured limit"):
        cfg.enforce_payload_limit(b"1234567890abcdefg")


def test_replay_window_configurable() -> None:
    cfg = SIFRConfig(
        mode=DeploymentMode.SINGLE_VERIFIER,
        key_store_uri="file:///secure/sifr-keystore.json",
        replay_window_seconds=42,
    )
    cfg.validate()
    cache = cfg.build_replay_cache()
    try:
        assert cache.window == timedelta(seconds=42)
    finally:
        cache.close()


def test_redacted_errors_do_not_expose_secrets() -> None:
    cfg = SIFRConfig(
        mode=DeploymentMode.SINGLE_VERIFIER,
        key_store_uri="file:///secure/sifr-keystore.json",
    )
    cfg.validate()
    err = cfg.redact_exception(
        RuntimeError("database password=swordfish token=abc123"),
        correlation_id="req-1",
    )
    encoded = json.dumps(err, sort_keys=True)
    assert "swordfish" not in encoded
    assert "abc123" not in encoded
    assert err["error"]["message"] == "error details redacted"
    assert err["error"]["type"] == "RuntimeError"
    assert err["error"]["correlation_id"] == "req-1"


def test_demo_mode_must_be_explicit() -> None:
    cfg = SIFRConfig(mode=DeploymentMode.DEMO, allow_demo_keys=False)
    with pytest.raises(ConfigError, match="explicitly set allow_demo_keys"):
        cfg.validate()
    demo = SIFRConfig.demo(demo_key_ids=("did:sifr:demo#key-1",))
    assert demo.is_demo_mode
    assert demo.allow_demo_keys


def test_rate_limit_parameters_validated() -> None:
    cfg = SIFRConfig(
        mode=DeploymentMode.SINGLE_VERIFIER,
        key_store_uri="file:///secure/sifr-keystore.json",
        rate_limit=RateLimitConfig(requests_per_minute=10, burst=11),
    )
    with pytest.raises(ConfigError, match="burst cannot exceed"):
        cfg.validate()
