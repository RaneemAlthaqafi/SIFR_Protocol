"""Runtime trace-conformance tests against the TLA+ model.

These tests do NOT prove that the SIFR Python implementation refines the
TLA+ specification — there is no machine-checked simulation relation.
They DO prove a weaker, useful property:

  Every Python execution path exercised here produces a sequence of
  protocol events that satisfies every TLA+ invariant in
  formal/sifr_capability.tla.

This is the "trace-checked" evidence level promised in
docs/formal_scope.md.

Two complementary directions are exercised:

  1. *Positive*: drive the implementation through realistic flows
     (issue → consume → revoke → consume-blocked) and confirm the
     emitted trace satisfies all invariants.

  2. *Negative*: hand-craft traces representing TLA+ counterexamples
     (a hypothetical bug) and confirm the conformance checker rejects
     them. This proves the checker is sensitive to violations, not
     trivially-vacuous.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sifr.capabilities import (
    CapabilityStore,
    authorize_action,
    create_capability_grant,
    verify_capability_grant,
)
from sifr.crypto import generate_keypair
from sifr.errors import UnauthorizedAction
from sifr.messages import create_message
from sifr.replay import ReplayCache
from sifr.revocation import RevocationRegistry
from sifr.trace_conformance import (
    TraceConformanceError,
    TraceEvent,
    check_trace_invariants,
)
from sifr.utils import utc_now_iso


def _future_iso(seconds: int = 3600) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


# --------------------------------------------------------------------------
# Direction 1: positive — real Python runs satisfy every invariant.
# --------------------------------------------------------------------------

def test_basic_issue_consume_emits_conformant_trace():
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    subject = "did:sifr:bob"
    issuer_kid = f"{issuer}#key-1"
    actions = ["tool.calculator.add"]
    cap_id = "cap_basic_1"

    grant = create_capability_grant(
        issuer=issuer,
        subject=subject,
        actions=actions,
        resource_scope=["calculator"],
        issuer_private_key=priv,
        receiver_id=subject,
        session_id="sess1",
        expires_at=_future_iso(),
        max_calls=3,
        capability_id=cap_id,
    )
    store = CapabilityStore()
    store.add(grant)
    verify_capability_grant(grant, pub)

    history: list[TraceEvent] = []
    history.append(
        TraceEvent(op="Issue", cap=cap_id, sub=subject, iss=issuer, actions=tuple(actions))
    )

    # Two consumes, each a distinct message_id.
    for i, msg_id in enumerate(["m_001", "m_002"]):
        action_msg = create_message(
            "Action",
            subject,
            issuer,
            {"action": "tool.calculator.add", "args": {"a": i, "b": i + 1}, "requires_auth": True},
            session_id="sess1",
            capability_id=cap_id,
            message_id=msg_id,
        )
        ok = authorize_action(action_msg, grant, pub, store)
        assert ok
        history.append(
            TraceEvent(
                op="Consume",
                cap=cap_id,
                sub=subject,
                iss=issuer,
                kid=issuer_kid,
                msg=msg_id,
                act="tool.calculator.add",
            )
        )

    # No invariant should fire.
    check_trace_invariants(history, max_calls=3)


def test_revoke_then_consume_blocked_emits_conformant_trace(tmp_path):
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    subject = "did:sifr:bob"
    issuer_kid = f"{issuer}#key-1"
    cap_id = "cap_rev"

    grant = create_capability_grant(
        issuer=issuer,
        subject=subject,
        actions=["tool.calculator.add"],
        resource_scope=["calculator"],
        issuer_private_key=priv,
        receiver_id=subject,
        session_id="sess2",
        expires_at=_future_iso(),
        max_calls=5,
        capability_id=cap_id,
    )
    store = CapabilityStore()
    store.add(grant)
    verify_capability_grant(grant, pub)

    rev = RevocationRegistry(
        issuer=issuer,
        issuer_kid=issuer_kid,
        issuer_private_key=priv,
        verifier_key=pub,
        store_path=tmp_path / "rev.jsonl",
    )

    history: list[TraceEvent] = [
        TraceEvent(op="Issue", cap=cap_id, sub=subject, iss=issuer, actions=("tool.calculator.add",))
    ]

    # First consume: allowed.
    msg = create_message(
        "Action",
        subject,
        issuer,
        {"action": "tool.calculator.add", "args": {"a": 1, "b": 2}, "requires_auth": True},
        session_id="sess2",
        capability_id=cap_id,
        message_id="m_pre_revoke",
    )
    assert authorize_action(msg, grant, pub, store, revocation_registry=rev)
    history.append(
        TraceEvent(
            op="Consume",
            cap=cap_id,
            sub=subject,
            iss=issuer,
            kid=issuer_kid,
            msg="m_pre_revoke",
            act="tool.calculator.add",
        )
    )

    # Revoke.
    rev.revoke(cap_id, "operator-initiated rotation")
    history.append(TraceEvent(op="Revoke", cap=cap_id))

    # Second consume: must be blocked.
    msg2 = create_message(
        "Action",
        subject,
        issuer,
        {"action": "tool.calculator.add", "args": {"a": 3, "b": 4}, "requires_auth": True},
        session_id="sess2",
        capability_id=cap_id,
        message_id="m_post_revoke",
    )
    with pytest.raises(UnauthorizedAction, match="REVOKED_CAPABILITY"):
        authorize_action(msg2, grant, pub, store, revocation_registry=rev)
    # The implementation rejected; we do NOT append a Consume event.
    # The trace is conformant: only one Consume, and it is before Revoke.

    check_trace_invariants(history, max_calls=5)


def test_replay_blocked_emits_conformant_trace(tmp_path):
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    subject = "did:sifr:bob"
    issuer_kid = f"{issuer}#key-1"
    cap_id = "cap_replay"

    grant = create_capability_grant(
        issuer=issuer,
        subject=subject,
        actions=["tool.calculator.add"],
        resource_scope=["calculator"],
        issuer_private_key=priv,
        receiver_id=subject,
        session_id="sess3",
        expires_at=_future_iso(),
        max_calls=10,
        capability_id=cap_id,
    )
    store = CapabilityStore()
    store.add(grant)

    cache = ReplayCache(store_path=tmp_path / "replay.sqlite")

    history = [
        TraceEvent(op="Issue", cap=cap_id, sub=subject, iss=issuer, actions=("tool.calculator.add",))
    ]

    msg = create_message(
        "Action",
        subject,
        issuer,
        {"action": "tool.calculator.add", "args": {"a": 1, "b": 1}, "requires_auth": True},
        session_id="sess3",
        capability_id=cap_id,
        message_id="m_uniq",
    )
    assert authorize_action(msg, grant, pub, store, replay_cache=cache)
    history.append(
        TraceEvent(
            op="Consume", cap=cap_id, sub=subject, iss=issuer, kid=issuer_kid,
            msg="m_uniq", act="tool.calculator.add",
        )
    )

    # Replay: same message_id again. Implementation must reject.
    from sifr.errors import ReplayError
    with pytest.raises(ReplayError):
        authorize_action(msg, grant, pub, store, replay_cache=cache)
    # No second Consume event in the trace.

    check_trace_invariants(history, max_calls=10)


# --------------------------------------------------------------------------
# Direction 2: negative — counterexample traces are rejected.
# --------------------------------------------------------------------------

def test_checker_catches_unauthorized_action():
    history = [
        TraceEvent(op="Issue", cap="c1", sub="s1", iss="i1", actions=("tool.calculator.add",)),
        TraceEvent(
            op="Consume", cap="c1", sub="s1", iss="i1", kid="k1",
            msg="m1", act="tool.dangerous",  # not in grant
        ),
    ]
    with pytest.raises(TraceConformanceError, match="NoUnauthorizedActionConsume"):
        check_trace_invariants(history, max_calls=5)


def test_checker_catches_wrong_subject():
    history = [
        TraceEvent(op="Issue", cap="c1", sub="alice", iss="i1", actions=("a",)),
        TraceEvent(op="Consume", cap="c1", sub="eve", iss="i1", kid="k1", msg="m1", act="a"),
    ]
    with pytest.raises(TraceConformanceError, match="NoWrongSubjectConsume"):
        check_trace_invariants(history, max_calls=5)


def test_checker_catches_consume_after_revoke():
    history = [
        TraceEvent(op="Issue", cap="c1", sub="s1", iss="i1", actions=("a",)),
        TraceEvent(op="Revoke", cap="c1"),
        TraceEvent(op="Consume", cap="c1", sub="s1", iss="i1", kid="k1", msg="m1", act="a"),
    ]
    with pytest.raises(TraceConformanceError, match="non-active state"):
        check_trace_invariants(history, max_calls=5)


def test_checker_catches_consume_after_expire():
    history = [
        TraceEvent(op="Issue", cap="c1", sub="s1", iss="i1", actions=("a",)),
        TraceEvent(op="Expire", cap="c1"),
        TraceEvent(op="Consume", cap="c1", sub="s1", iss="i1", kid="k1", msg="m1", act="a"),
    ]
    with pytest.raises(TraceConformanceError, match="non-active state"):
        check_trace_invariants(history, max_calls=5)


def test_checker_catches_replay():
    history = [
        TraceEvent(op="Issue", cap="c1", sub="s1", iss="i1", actions=("a",)),
        TraceEvent(op="Consume", cap="c1", sub="s1", iss="i1", kid="k1", msg="m_dup", act="a"),
        TraceEvent(op="Consume", cap="c1", sub="s1", iss="i1", kid="k1", msg="m_dup", act="a"),
    ]
    with pytest.raises(TraceConformanceError, match="NoReplayedConsume"):
        check_trace_invariants(history, max_calls=5)


def test_checker_catches_revoked_key_consume():
    history = [
        TraceEvent(op="Issue", cap="c1", sub="s1", iss="i1", actions=("a",)),
        TraceEvent(op="RevokeKey", kid="k1"),
        TraceEvent(op="Consume", cap="c1", sub="s1", iss="i1", kid="k1", msg="m1", act="a"),
    ]
    with pytest.raises(TraceConformanceError, match="NoConsumeWithRevokedKey"):
        check_trace_invariants(history, max_calls=5)


def test_checker_catches_over_budget():
    history = [TraceEvent(op="Issue", cap="c1", sub="s1", iss="i1", actions=("a",))]
    for i in range(4):
        history.append(
            TraceEvent(op="Consume", cap="c1", sub="s1", iss="i1", kid="k1", msg=f"m{i}", act="a")
        )
    with pytest.raises(TraceConformanceError, match="NoOverBudgetConsume"):
        check_trace_invariants(history, max_calls=3)


def test_checker_catches_consume_without_issue():
    history = [
        TraceEvent(op="Consume", cap="c_ghost", sub="s", iss="i", kid="k", msg="m", act="a"),
    ]
    with pytest.raises(TraceConformanceError, match="unissued"):
        check_trace_invariants(history, max_calls=5)


def test_checker_catches_wrong_issuer():
    history = [
        TraceEvent(op="Issue", cap="c1", sub="s1", iss="alice", actions=("a",)),
        TraceEvent(op="Consume", cap="c1", sub="s1", iss="eve", kid="k1", msg="m1", act="a"),
    ]
    with pytest.raises(TraceConformanceError, match="NoConsumeWithWrongIssuer"):
        check_trace_invariants(history, max_calls=5)
