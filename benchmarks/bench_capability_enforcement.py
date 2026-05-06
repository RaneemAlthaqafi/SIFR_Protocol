from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.capabilities import CapabilityStore, authorize_action, create_capability_grant
from sifr.crypto import generate_keypair, sign_message
from sifr.messages import create_message


def scenario(max_calls=2, expires_delta=10, subject="did:sifr:a"):
    a_priv, _ = generate_keypair(); b_priv, b_pub = generate_keypair()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=expires_delta)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    grant = create_capability_grant("did:sifr:b", subject, ["tool.calculator.add"], ["demo/calculator"], issuer_private_key=b_priv, receiver_id="did:sifr:a", session_id="s", expires_at=expires, max_calls=max_calls)
    store = CapabilityStore(); store.add(grant)
    action = sign_message(create_message("Action", "did:sifr:a", "did:sifr:b", {"action": "tool.calculator.add", "args": {"a": 2, "b": 3}}, session_id="s", capability_id=grant["payload"]["capability_id"]), a_priv)
    return grant, action, b_pub, store


def attempt(name, fn):
    try:
        fn()
        return {"case": name, "passed": True, "error": None}
    except Exception as exc:
        return {"case": name, "passed": False, "error": str(exc)}


def main() -> None:
    rows = []
    g, a, pub, s = scenario(); rows.append(attempt("authorized_action", lambda: authorize_action(a, g, pub, s)))
    g, a, pub, s = scenario(); a["payload"]["action"] = "tool.files.delete"; rows.append(attempt("unauthorized_action", lambda: authorize_action(a, g, pub, s)))
    g, a, pub, s = scenario(expires_delta=-1); rows.append(attempt("expired_capability", lambda: authorize_action(a, g, pub, s)))
    g, a, pub, s = scenario(); g2 = copy.deepcopy(g); g2["payload"]["actions"] = ["tool.files.delete"]; rows.append(attempt("tampered_capability", lambda: authorize_action(a, g2, pub, s)))
    g, a, pub, s = scenario(max_calls=1); authorize_action(a, g, pub, s); rows.append(attempt("over_budget_capability", lambda: authorize_action(a, g, pub, s)))
    g, a, pub, s = scenario(subject="did:sifr:other"); rows.append(attempt("wrong_subject", lambda: authorize_action(a, g, pub, s)))
    out = Path("benchmarks/results/capability_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
