from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.audit_dag import AuditDAG
from sifr.capabilities import CapabilityStore, authorize_action, create_capability_grant, verify_capability_grant
from sifr.crypto import generate_keypair, public_key_to_b64, sha256_cid, sign_message, verify_message
from sifr.messages import create_message
from sifr.wasm_runner import CalculatorTool


def run_demo() -> int:
    print("=== SIFR v0.1 Two-Agent Demo ===")
    agent_a = "did:sifr:planner"
    agent_b = "did:sifr:executor"
    print(f"Agent A: {agent_a}")
    print(f"Agent B: {agent_b}")

    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    session_id = "sess_demo_two_agents"
    dag = AuditDAG()
    store = CapabilityStore()

    hello = sign_message(create_message("Hello", agent_a, agent_b, {
        "agent_name": "PlannerAgent",
        "supported_versions": ["sifr/0.1"],
        "supported_features": ["signing", "capabilities", "audit_dag", "tensor_frame"],
        "public_key": public_key_to_b64(a_pub),
    }, session_id=session_id), a_priv)
    verify_message(hello, a_pub)
    hello_cid = dag.add_message(hello)
    print("Hello verified: OK")

    offer = sign_message(create_message("CapabilityOffer", agent_b, agent_a, {
        "offered_actions": [{
            "action": "tool.calculator.add",
            "description": "Adds two numbers",
            "input_schema": {"a": "number", "b": "number"},
            "output_schema": {"result": "number"},
        }]
    }, session_id=session_id, parents=[hello_cid]), b_priv)
    offer_cid = dag.add_message(offer)
    print("Capability offered: tool.calculator.add")

    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    grant = create_capability_grant(agent_b, agent_a, ["tool.calculator.add"], ["demo/calculator"],
                                    issuer_private_key=b_priv, receiver_id=agent_a, session_id=session_id,
                                    expires_at=expires, max_calls=5)
    grant["parents"] = [offer_cid]
    grant = sign_message(grant, b_priv)
    verify_capability_grant(grant, b_pub)
    store.add(grant)
    grant_cid = dag.add_message(grant)
    cap_id = grant["payload"]["capability_id"]
    print("Capability granted: OK")

    action = sign_message(create_message("Action", agent_a, agent_b, {
        "action": "tool.calculator.add",
        "args": {"a": 2, "b": 3},
    }, session_id=session_id, parents=[grant_cid], capability_id=cap_id), a_priv)
    verify_message(action, a_pub)
    action_cid = dag.add_message(action)
    print("Action signed: OK")
    authorize_action(action, grant, b_pub, store)
    print("Action authorized: OK")

    tool = CalculatorTool()
    result = tool.execute(action["payload"]["action"], action["payload"]["args"])
    tooluse = sign_message(create_message("ToolUse", agent_b, agent_a, {
        "tool": "calculator",
        "operation": "add",
        "args_hash": sha256_cid({"payload": action["payload"]}),
        "sandbox": "python_stub",
        "status": "executed",
    }, session_id=session_id, parents=[action_cid], capability_id=cap_id), b_priv)
    tooluse_cid = dag.add_message(tooluse)
    print("Tool executed: calculator.add")

    observation = sign_message(create_message("Observation", agent_b, agent_a, {
        "ref_action_id": action["message_id"],
        "status": "success",
        "data": result,
    }, session_id=session_id, parents=[tooluse_cid]), b_priv)
    verify_message(observation, b_pub)
    obs_cid = dag.add_message(observation)
    print("Observation verified: OK")

    final = sign_message(create_message("Result", agent_a, agent_b, {
        "status": "complete",
        "summary": "The result of 2 + 3 is 5.",
    }, session_id=session_id, parents=[obs_cid]), a_priv)
    dag.add_message(final)
    print(f"Result: {result['result']}")
    dag.verify_dag_integrity()
    print("Audit DAG integrity: OK")
    print("Demo completed successfully.")
    return result["result"]


if __name__ == "__main__":
    run_demo()
