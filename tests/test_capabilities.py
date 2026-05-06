from datetime import datetime, timedelta, timezone
import copy
import pytest

from sifr.capabilities import CapabilityStore, authorize_action, create_capability_grant
from sifr.crypto import generate_keypair, sign_message
from sifr.errors import SignatureError, UnauthorizedAction
from sifr.messages import create_message


def make_flow(max_calls=2, expires_delta=10, subject="did:sifr:a"):
    a_priv, _ = generate_keypair()
    b_priv, b_pub = generate_keypair()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=expires_delta)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    grant = create_capability_grant("did:sifr:b", subject, ["tool.calculator.add"], ["demo/calculator"], issuer_private_key=b_priv, receiver_id="did:sifr:a", session_id="s", expires_at=expires, max_calls=max_calls)
    store = CapabilityStore()
    store.add(grant)
    action = sign_message(create_message("Action", "did:sifr:a", "did:sifr:b", {"action": "tool.calculator.add", "args": {"a": 2, "b": 3}}, session_id="s", capability_id=grant["payload"]["capability_id"]), a_priv)
    return grant, action, b_pub, store


def test_valid_grant_allows_action():
    grant, action, b_pub, store = make_flow()
    assert authorize_action(action, grant, b_pub, store)


def test_wrong_subject_rejected():
    grant, action, b_pub, store = make_flow(subject="did:sifr:other")
    with pytest.raises(UnauthorizedAction):
        authorize_action(action, grant, b_pub, store)


def test_wrong_action_rejected():
    grant, action, b_pub, store = make_flow()
    action["payload"]["action"] = "tool.files.delete"
    with pytest.raises(UnauthorizedAction):
        authorize_action(action, grant, b_pub, store)


def test_expired_grant_rejected():
    grant, action, b_pub, store = make_flow(expires_delta=-1)
    with pytest.raises(UnauthorizedAction):
        authorize_action(action, grant, b_pub, store)


def test_over_budget_grant_rejected():
    grant, action, b_pub, store = make_flow(max_calls=1)
    authorize_action(action, grant, b_pub, store)
    with pytest.raises(UnauthorizedAction):
        authorize_action(action, grant, b_pub, store)


def test_tampered_grant_rejected():
    grant, action, b_pub, store = make_flow()
    grant = copy.deepcopy(grant)
    grant["payload"]["actions"] = ["tool.files.delete"]
    with pytest.raises(SignatureError):
        authorize_action(action, grant, b_pub, store)
