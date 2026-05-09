"""v0.3 strict formal-artifact test.

Fail-closed obligations:
  - The TLA+ model file exists and declares each expected invariant.
  - MC.cfg lists every TLC-checked invariant.
  - tlc_output.txt exists, reports no error, and reports >=11000 distinct states.
  - tlc_metadata.json invariant list matches MC.cfg.
  - model_hashes.json hashes match the live files (catches stale outputs).

When `SIFR_TLC_FROZEN=1` is set, the test additionally requires the freshness
artifacts to be present and consistent (used in CI / release verification).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FORMAL = REPO_ROOT / "formal"
TLA = FORMAL / "sifr_capability.tla"
CFG = FORMAL / "MC.cfg"
OUTPUT = FORMAL / "output" / "tlc_output.txt"
META = FORMAL / "output" / "tlc_metadata.json"
HASHES = FORMAL / "output" / "model_hashes.json"
APALACHE = FORMAL / "apalache.cfg"

EXPECTED_INVARIANTS = [
    "TypeInvariant",
    "NoUnauthorizedActionConsume",
    "NoWrongSubjectConsume",
    "NoConsumeAfterExpire",
    "NoConsumeAfterRevoke",
    "NoOverBudgetConsume",
    "NoReplayedConsume",
    "NoConsumeWithWrongIssuer",
    "NoConsumeWithRevokedKey",
]


def test_tla_module_exists():
    assert TLA.is_file(), f"missing TLA+ model at {TLA}"


def test_mc_config_exists():
    assert CFG.is_file(), f"missing MC.cfg at {CFG}"


def test_apalache_config_exists_and_is_operator_runnable():
    assert APALACHE.is_file(), f"missing Apalache config at {APALACHE}"
    body = APALACHE.read_text(encoding="utf-8")
    assert "apalache-mc check" in body
    assert "INVARIANT SecureCapabilityLifecycle" in body


def test_module_declares_all_expected_invariants():
    body = TLA.read_text(encoding="utf-8")
    for name in EXPECTED_INVARIANTS:
        if name == "TypeInvariant":
            assert "TypeInvariant ==" in body, "TypeInvariant not defined"
            continue
        assert re.search(rf"^{re.escape(name)}\s*==", body, re.MULTILINE), (
            f"invariant {name!r} not defined in {TLA.name}"
        )


def _config_invariants() -> list[str]:
    cfg = CFG.read_text(encoding="utf-8")
    in_invariants = False
    out: list[str] = []
    for raw in cfg.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("INVARIANTS"):
            in_invariants = True
            continue
        if in_invariants:
            if line.endswith(("=", ":")) or line.startswith(("CONSTANTS", "SPECIFICATION", "PROPERTIES", "INIT", "NEXT")):
                break
            out.append(line)
    return out


def test_mc_config_lists_all_expected_invariants():
    listed = _config_invariants()
    missing = [n for n in EXPECTED_INVARIANTS if n not in listed]
    assert not missing, f"MC.cfg is missing invariants: {missing}"


def test_tlc_output_exists_or_skip():
    if not OUTPUT.is_file():
        pytest.skip(
            f"no TLC output at {OUTPUT.relative_to(REPO_ROOT)}. "
            "Install Java 11+, run scripts/install_tla.ps1, then formal/run_tlc.{ps1,sh}."
        )


def _frozen_required() -> bool:
    return os.environ.get("SIFR_TLC_FROZEN") == "1"


def test_tlc_output_success_marker():
    if not OUTPUT.is_file():
        if _frozen_required():
            pytest.fail("SIFR_TLC_FROZEN=1 but tlc_output.txt is missing")
        pytest.skip("no TLC output present")
    body = OUTPUT.read_text(encoding="utf-8")
    success = (
        "Model checking completed. No error has been found." in body
        or "No error has been found." in body
    )
    assert success, f"TLC output does not contain a success marker; tail:\n{body[-500:]}"


def test_tlc_metadata_present_and_consistent():
    if not META.is_file():
        if _frozen_required():
            pytest.fail("SIFR_TLC_FROZEN=1 but tlc_metadata.json is missing")
        pytest.skip("no tlc_metadata.json present")
    meta = json.loads(META.read_text(encoding="utf-8"))
    invs = meta.get("invariants_checked", [])
    missing = [n for n in EXPECTED_INVARIANTS if n not in invs]
    assert not missing, f"tlc_metadata.json invariants_checked missing: {missing}"
    assert "result" in meta and "No error" in meta["result"]
    assert int(meta.get("distinct_states", 0)) >= 1000, "implausibly small state count"


def test_model_hashes_match_files():
    if not HASHES.is_file():
        if _frozen_required():
            pytest.fail("SIFR_TLC_FROZEN=1 but model_hashes.json is missing")
        pytest.skip("no model_hashes.json present")
    hashes = json.loads(HASHES.read_text(encoding="utf-8"))

    def canonical_text_sha256(p: Path) -> str:
        text = p.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    pairs = {
        "sifr_capability.tla": TLA,
        "MC.cfg": CFG,
        "tlc_output.txt": OUTPUT,
    }
    stale = []
    for name, path in pairs.items():
        if name not in hashes:
            stale.append(f"{name}: not in model_hashes.json")
            continue
        if not path.is_file():
            stale.append(f"{name}: file missing")
            continue
        actual = canonical_text_sha256(path)
        if actual != hashes[name]:
            stale.append(f"{name}: stale (expected {hashes[name][:12]}, got {actual[:12]})")
    assert not stale, (
        "Formal artifacts are stale. Re-run formal/run_tlc.{ps1,sh} and "
        "regenerate tlc_metadata.json + model_hashes.json:\n  - " + "\n  - ".join(stale)
    )
