"""Runtime trace-conformance checker.

This module bridges the SIFR Python implementation and the TLA+ model in
`formal/sifr_capability.tla`. It does NOT replace the TLA+ proof: it is a
conformance check.

A `TraceEvent` records one observable action in the protocol — `Issue`,
`Expire`, `Revoke`, `RevokeKey`, or `Consume` — together with the bound
identifiers. `check_trace_invariants` re-evaluates the same invariants
expressed in TLA+ over the recorded trace, and raises if any holds-by-
construction-in-the-spec property is violated by the implementation.

This gives us:

  - **trace-checked** evidence that every implementation action produces a
    state transition consistent with the TLA+ transition relation;
  - **counterexample-replay** capability: a TLA+ counterexample, written as
    a sequence of TraceEvents, can be replayed in pytest to assert the
    impl rejects it.

Honest non-claim: this is not a refinement proof. There is no machine-
checked simulation relation from Python to TLA+. The conformance check
verifies *trace-level invariants*, not *implementation soundness*. A bug
that violates an invariant in the implementation but happens not to fire
during the test run will not be caught.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


__all__ = [
    "TraceEvent",
    "TraceConformanceError",
    "check_trace_invariants",
    "trace_from_events",
]


class TraceConformanceError(Exception):
    """Raised when a recorded trace violates a TLA+ invariant."""


@dataclass(frozen=True)
class TraceEvent:
    op: str  # "Issue" | "Expire" | "Revoke" | "RevokeKey" | "Consume"
    cap: Optional[str] = None
    sub: Optional[str] = None
    iss: Optional[str] = None
    kid: Optional[str] = None
    msg: Optional[str] = None
    act: Optional[str] = None
    actions: tuple[str, ...] = ()  # for Issue: the granted action set


def trace_from_events(events: Iterable[TraceEvent]) -> list[TraceEvent]:
    return list(events)


def _check_no_unissued_consume(history: list[TraceEvent], state: dict, granted: dict) -> None:
    """I0: every Consume targets a previously-Issued capability."""
    issued: set[str] = set()
    for ev in history:
        if ev.op == "Issue":
            issued.add(ev.cap)
        elif ev.op == "Consume" and ev.cap not in issued:
            raise TraceConformanceError(
                f"Consume targets unissued capability {ev.cap!r}: {ev}"
            )


def _check_action_in_grant(history: list[TraceEvent]) -> None:
    """TLA+ NoUnauthorizedActionConsume.

    Every Consume's `act` must be in the action set the cap was issued with.
    """
    granted: dict[str, set[str]] = {}
    for ev in history:
        if ev.op == "Issue":
            granted[ev.cap] = set(ev.actions)
        elif ev.op == "Consume":
            allowed = granted.get(ev.cap)
            if allowed is None:
                raise TraceConformanceError(
                    f"Consume on un-Issued cap {ev.cap!r}: {ev}"
                )
            if ev.act not in allowed:
                raise TraceConformanceError(
                    f"NoUnauthorizedActionConsume violated: {ev.act!r} not in {allowed!r}"
                )


def _check_subject_match(history: list[TraceEvent]) -> None:
    """TLA+ NoWrongSubjectConsume."""
    binding: dict[str, str] = {}  # cap -> sub
    for ev in history:
        if ev.op == "Issue":
            binding[ev.cap] = ev.sub
        elif ev.op == "Consume":
            if binding.get(ev.cap) != ev.sub:
                raise TraceConformanceError(
                    f"NoWrongSubjectConsume violated: cap {ev.cap!r} subject "
                    f"{binding.get(ev.cap)!r} but Consume subject {ev.sub!r}"
                )


def _check_issuer_match(history: list[TraceEvent]) -> None:
    """TLA+ NoConsumeWithWrongIssuer."""
    binding: dict[str, str] = {}  # cap -> iss
    for ev in history:
        if ev.op == "Issue":
            binding[ev.cap] = ev.iss
        elif ev.op == "Consume":
            if binding.get(ev.cap) != ev.iss:
                raise TraceConformanceError(
                    f"NoConsumeWithWrongIssuer violated: cap {ev.cap!r} issuer "
                    f"{binding.get(ev.cap)!r} but Consume issuer {ev.iss!r}"
                )


def _check_no_consume_after_terminal(history: list[TraceEvent]) -> None:
    """TLA+ NoConsumeAfterRevoke and NoConsumeAfterExpire combined."""
    state: dict[str, str] = {}  # cap -> {"unissued","active","expired","revoked"}
    for ev in history:
        if ev.op == "Issue":
            state[ev.cap] = "active"
        elif ev.op == "Expire":
            if state.get(ev.cap) == "active":
                state[ev.cap] = "expired"
        elif ev.op == "Revoke":
            if state.get(ev.cap) == "active":
                state[ev.cap] = "revoked"
        elif ev.op == "Consume":
            if state.get(ev.cap) != "active":
                raise TraceConformanceError(
                    f"Consume on cap {ev.cap!r} in non-active state {state.get(ev.cap)!r}"
                )


def _check_no_consume_with_revoked_key(history: list[TraceEvent]) -> None:
    """TLA+ NoConsumeWithRevokedKey."""
    revoked_kids: set[str] = set()
    for ev in history:
        if ev.op == "RevokeKey":
            revoked_kids.add(ev.kid)
        elif ev.op == "Consume":
            if ev.kid in revoked_kids:
                raise TraceConformanceError(
                    f"NoConsumeWithRevokedKey violated: kid {ev.kid!r} was revoked"
                )


def _check_no_replay(history: list[TraceEvent]) -> None:
    """TLA+ NoReplayedConsume."""
    seen: set[tuple[Optional[str], Optional[str]]] = set()
    for ev in history:
        if ev.op == "Consume":
            key = (ev.sub, ev.msg)
            if key in seen:
                raise TraceConformanceError(
                    f"NoReplayedConsume violated: (sub={ev.sub!r}, msg={ev.msg!r}) twice"
                )
            seen.add(key)


def _check_budget(history: list[TraceEvent], max_calls: int) -> None:
    """TLA+ NoOverBudgetConsume.

    Counts Consume per cap and asserts <= max_calls. Caller passes the
    bound used in the test harness (the model is parametric in MaxCalls).
    """
    used: dict[str, int] = {}
    for ev in history:
        if ev.op == "Consume":
            used[ev.cap] = used.get(ev.cap, 0) + 1
            if used[ev.cap] > max_calls:
                raise TraceConformanceError(
                    f"NoOverBudgetConsume violated: cap {ev.cap!r} used "
                    f"{used[ev.cap]} times (max {max_calls})"
                )


def check_trace_invariants(
    history: Iterable[TraceEvent],
    *,
    max_calls: int,
) -> None:
    """Run every TLA+ invariant over `history`.

    Raises TraceConformanceError on the first violation.
    """
    history_list = list(history)
    _check_no_unissued_consume(history_list, state={}, granted={})
    _check_action_in_grant(history_list)
    _check_subject_match(history_list)
    _check_issuer_match(history_list)
    _check_no_consume_after_terminal(history_list)
    _check_no_consume_with_revoked_key(history_list)
    _check_no_replay(history_list)
    _check_budget(history_list, max_calls)
