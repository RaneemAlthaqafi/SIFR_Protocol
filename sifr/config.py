"""Production configuration guardrails for SIFR verifier deployments.

The defaults fail closed for non-demo modes: production deployments must
configure durable key storage and may not opt into demo key material. The
module is intentionally small and framework-neutral so examples, tests, and
real services can share the same validation path.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional

from .canonical import canonical_json
from .errors import SIFRError
from .replay import ReplayCache

__all__ = [
    "ConfigError",
    "DeploymentMode",
    "RateLimitConfig",
    "SIFRConfig",
]


class ConfigError(SIFRError):
    """Raised when SIFR configuration is missing or unsafe."""


class DeploymentMode(str, Enum):
    """Documented verifier deployment profiles."""

    SINGLE_VERIFIER = "single_verifier"
    CLUSTERED_VERIFIER = "clustered_verifier"
    MULTI_TENANT_VERIFIER = "multi_tenant_verifier"
    DEMO = "development_demo"


@dataclass(frozen=True)
class RateLimitConfig:
    """Optional process-local rate-limit hints.

    These values are configuration only. Enforcement belongs in the hosting
    service or reverse proxy so it can be shared across workers.
    """

    requests_per_minute: int = 600
    burst: int = 60

    def validate(self) -> None:
        if self.requests_per_minute <= 0:
            raise ConfigError("rate limit requests_per_minute must be positive")
        if self.burst <= 0:
            raise ConfigError("rate limit burst must be positive")
        if self.burst > self.requests_per_minute:
            raise ConfigError("rate limit burst cannot exceed requests_per_minute")


@dataclass(frozen=True)
class SIFRConfig:
    """Validated runtime configuration for SIFR verifier services."""

    mode: DeploymentMode = DeploymentMode.SINGLE_VERIFIER
    key_store_uri: Optional[str] = None
    replay_store_uri: Optional[str] = None
    revocation_log_uri: Optional[str] = None
    max_payload_bytes: int = 1_048_576
    replay_window_seconds: int = 300
    redact_errors: bool = True
    allow_demo_keys: bool = False
    demo_key_ids: tuple[str, ...] = ()
    tenant_id: Optional[str] = None
    rate_limit: Optional[RateLimitConfig] = field(default_factory=RateLimitConfig)

    @property
    def is_demo_mode(self) -> bool:
        return self.mode == DeploymentMode.DEMO

    @property
    def is_production_mode(self) -> bool:
        return not self.is_demo_mode

    @classmethod
    def demo(cls, **overrides: Any) -> "SIFRConfig":
        """Construct an explicit demo-mode configuration."""

        data: dict[str, Any] = {
            "mode": DeploymentMode.DEMO,
            "allow_demo_keys": True,
            "redact_errors": False,
            "max_payload_bytes": 256 * 1024,
            "replay_window_seconds": 300,
            "rate_limit": None,
        }
        data.update(overrides)
        cfg = cls(**data)
        cfg.validate()
        return cfg

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "SIFRConfig":
        """Load configuration from environment variables and validate it."""

        env = os.environ if environ is None else environ
        mode = DeploymentMode(env.get("SIFR_MODE", DeploymentMode.SINGLE_VERIFIER.value))
        rate_limit: Optional[RateLimitConfig]
        if env.get("SIFR_RATE_LIMIT_DISABLED", "").lower() in {"1", "true", "yes"}:
            rate_limit = None
        else:
            rate_limit = RateLimitConfig(
                requests_per_minute=int(env.get("SIFR_RATE_LIMIT_RPM", "600")),
                burst=int(env.get("SIFR_RATE_LIMIT_BURST", "60")),
            )
        demo_ids = tuple(
            item.strip()
            for item in env.get("SIFR_DEMO_KEY_IDS", "").split(",")
            if item.strip()
        )
        cfg = cls(
            mode=mode,
            key_store_uri=env.get("SIFR_KEY_STORE_URI") or None,
            replay_store_uri=env.get("SIFR_REPLAY_STORE_URI") or None,
            revocation_log_uri=env.get("SIFR_REVOCATION_LOG_URI") or None,
            max_payload_bytes=int(env.get("SIFR_MAX_PAYLOAD_BYTES", "1048576")),
            replay_window_seconds=int(env.get("SIFR_REPLAY_WINDOW_SECONDS", "300")),
            redact_errors=env.get("SIFR_REDACT_ERRORS", "true").lower()
            not in {"0", "false", "no"},
            allow_demo_keys=env.get("SIFR_ALLOW_DEMO_KEYS", "false").lower()
            in {"1", "true", "yes"},
            demo_key_ids=demo_ids,
            tenant_id=env.get("SIFR_TENANT_ID") or None,
            rate_limit=rate_limit,
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.max_payload_bytes <= 0:
            raise ConfigError("max_payload_bytes must be positive")
        if self.max_payload_bytes > 16 * 1024 * 1024:
            raise ConfigError("max_payload_bytes must not exceed 16 MiB")
        if self.replay_window_seconds <= 0:
            raise ConfigError("replay_window_seconds must be positive")
        if self.replay_window_seconds > 24 * 60 * 60:
            raise ConfigError("replay_window_seconds must not exceed 24 hours")
        if self.rate_limit is not None:
            self.rate_limit.validate()

        if self.is_demo_mode:
            if not self.allow_demo_keys:
                raise ConfigError("demo mode must explicitly set allow_demo_keys=True")
            return

        if self.allow_demo_keys or self.demo_key_ids:
            raise ConfigError("demo keys are forbidden outside explicit demo mode")
        if not self.redact_errors:
            raise ConfigError("production modes must redact structured errors")
        if not self.key_store_uri:
            raise ConfigError("production modes require SIFR_KEY_STORE_URI")
        if self.key_store_uri.startswith("demo:") or "demo" in self.key_store_uri.lower():
            raise ConfigError("production key_store_uri must not reference demo keys")
        if self.mode in {
            DeploymentMode.CLUSTERED_VERIFIER,
            DeploymentMode.MULTI_TENANT_VERIFIER,
        }:
            if not self.replay_store_uri:
                raise ConfigError("clustered modes require durable replay_store_uri")
            if not self.revocation_log_uri:
                raise ConfigError("clustered modes require revocation_log_uri")
        if self.mode == DeploymentMode.MULTI_TENANT_VERIFIER and not self.tenant_id:
            raise ConfigError("multi-tenant mode requires tenant_id")

    def enforce_payload_limit(self, payload: bytes | str | Mapping[str, Any]) -> None:
        """Raise ConfigError when a frame body exceeds the configured limit."""

        if isinstance(payload, bytes):
            size = len(payload)
        elif isinstance(payload, str):
            size = len(payload.encode("utf-8"))
        else:
            size = len(canonical_json(dict(payload)))
        if size > self.max_payload_bytes:
            raise ConfigError(
                f"payload size {size} exceeds configured limit {self.max_payload_bytes}"
            )

    def build_replay_cache(self) -> ReplayCache:
        """Create a ReplayCache using the configured window and store."""

        return ReplayCache(
            window_seconds=self.replay_window_seconds,
            store_path=self.replay_store_uri,
        )

    def redact_exception(
        self,
        exc: BaseException,
        *,
        correlation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Return a structured error payload safe for logs or API responses."""

        error_type = exc.__class__.__name__
        if self.redact_errors:
            message = "error details redacted"
        else:
            message = str(exc)
        body: dict[str, Any] = {
            "ok": False,
            "error": {
                "type": error_type,
                "message": message,
            },
        }
        if correlation_id is not None:
            body["error"]["correlation_id"] = correlation_id
        # json round-trip catches accidental unserializable exception fields.
        json.dumps(body, sort_keys=True)
        return body
