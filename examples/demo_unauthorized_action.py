from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.capabilities import CapabilityStore, UnauthorizedAction, authorize_action, create_capability_grant
from sifr.crypto import generate_keypair, sign_message
from sifr.messages import create_message


def run_demo() -> str:
    agent_a = "did:sifr:planner"
    agent_b = "did:sifr:executor"
    a_priv, _ = generate_keypair()
    b_priv, b_pub = generate_keypair()
    session_id = "sess_unauthorized_demo"
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    grant = create_capability_grant(agent_b, agent_a, ["tool.calculator.add"], ["demo/calculator"],
                                    issuer_private_key=b_priv, receiver_id=agent_a, session_id=session_id,
                                    expires_at=expires, max_calls=1)
    store = CapabilityStore()
    store.add(grant)
    action = sign_message(create_message("Action", agent_a, agent_b, {
        "action": "tool.files.delete",
        "args": {"path": "/tmp/demo"},
    }, session_id=session_id, capability_id=grant["payload"]["capability_id"]), a_priv)
    try:
        authorize_action(action, grant, b_pub, store)
    except UnauthorizedAction as exc:
        print(str(exc))
        return str(exc)
    raise AssertionError("unauthorized action was not rejected")


if __name__ == "__main__":
    run_demo()
