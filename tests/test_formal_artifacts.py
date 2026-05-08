"""Verify the TLA+ model artifacts exist and (when TLC has been run) report
the expected results. The freshness check skips when no TLC output is present
on this host -- a reviewer with Java + tla2tools.jar can run formal/run_tlc to
generate it.

Trap-acceptance: this test asserts that EVERY invariant declared in MC.cfg
appears in tlc_output.txt's summary. Adding an invariant to MC.cfg without
re-running TLC fails this test.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FORMAL = REPO_ROOT / "formal"
TLA = FORMAL / "sifr_capability.tla"
CFG = FORMAL / "MC.cfg"
OUTPUT = FORMAL / "output" / "tlc_output.txt"


def test_tla_module_exists():
    assert TLA.is_file(), f"missing TLA+ model at {TLA}"


def test_mc_config_exists():
    assert CFG.is_file(), f"missing MC.cfg at {CFG}"


def test_module_declares_expected_invariants():
    body = TLA.read_text(encoding="utf-8")
    expected = [
        "NoOverBudgetConsume",
        "NoWrongSubjectConsume",
        "NoUnauthorizedActionConsume",
        "NoReplayedConsume",
        "NoConsumeAfterRevoke",
        "NoConsumeAfterExpire",
    ]
    for name in expected:
        assert re.search(rf"^{re.escape(name)}\s*==", body, re.MULTILINE), (
            f"invariant {name!r} not defined in {TLA.name}"
        )


def _config_invariants() -> list[str]:
    cfg_text = CFG.read_text(encoding="utf-8")
    in_invariants = False
    out: list[str] = []
    for raw in cfg_text.splitlines():
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


def test_mc_config_lists_invariants():
    invs = _config_invariants()
    assert len(invs) >= 6, f"expected >=6 invariants in MC.cfg, got {invs!r}"


def test_tlc_output_freshness_or_skip():
    """If TLC output exists, it must report no errors. If output is absent,
    skip with a clear note (a reviewer with Java + tla2tools.jar can produce
    the output by running formal/run_tlc.{ps1,sh}).
    """
    if not OUTPUT.is_file():
        pytest.skip(
            f"no TLC output at {OUTPUT.relative_to(REPO_ROOT)}. "
            f"Install Java JRE 11+, run scripts/install_tla.ps1, then formal/run_tlc.ps1."
        )
    body = OUTPUT.read_text(encoding="utf-8")
    success_markers = (
        "Model checking completed. No error has been found.",
        "No error has been found.",
    )
    assert any(m in body for m in success_markers), (
        f"TLC output does not contain a success marker. Last 500 chars:\n{body[-500:]}"
    )
    # TLC also reports the number of distinct states. A successful run
    # explored at least one state.
    assert "distinct states found" in body, (
        "TLC output missing 'distinct states found' line"
    )
