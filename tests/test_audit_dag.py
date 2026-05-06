import pytest

from sifr.audit_dag import AuditDAG
from sifr.crypto import generate_keypair, sign_message
from sifr.errors import AuditDAGError
from sifr.messages import create_message


def signed_msg(t, parents=None):
    priv, _ = generate_keypair()
    return sign_message(create_message(t, "did:sifr:a", "did:sifr:b", {"content": t}, parents=parents or []), priv)


def test_valid_dag_verifies():
    dag = AuditDAG()
    a = dag.add_message(signed_msg("Thought"))
    dag.add_message(signed_msg("Result", [a]))
    assert dag.verify_dag_integrity()


def test_missing_parent_detected():
    dag = AuditDAG()
    dag.add_message(signed_msg("Result", ["sha256:missing"]))
    assert dag.detect_missing_parent()
    with pytest.raises(AuditDAGError):
        dag.verify_dag_integrity()


def test_tampered_node_detected():
    dag = AuditDAG()
    cid = dag.add_message(signed_msg("Thought"))
    dag.messages[cid]["payload"]["content"] = "changed"
    assert dag.detect_tampering() == [cid]


def test_lineage_correct():
    dag = AuditDAG()
    a = dag.add_message(signed_msg("Thought"))
    b = dag.add_message(signed_msg("Result", [a]))
    assert [n["cid"] for n in dag.get_lineage(b)] == [a, b]


def test_export_jsonl_exists(tmp_path):
    dag = AuditDAG()
    dag.add_message(signed_msg("Thought"))
    out = tmp_path / "dag.jsonl"
    dag.export_jsonl(out)
    assert out.exists()
