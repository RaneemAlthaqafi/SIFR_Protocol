from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .crypto import sha256_cid
from .errors import AuditDAGError


class AuditDAG:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.messages: dict[str, dict[str, Any]] = {}

    def add_message(self, message: dict[str, Any], *, signature_valid: bool = True) -> str:
        cid = sha256_cid(message)
        node = {
            "cid": cid,
            "message_id": message["message_id"],
            "type": message["type"],
            "sender_id": message["sender_id"],
            "receiver_id": message["receiver_id"],
            "parents": list(message.get("parents", [])),
            "timestamp": message["timestamp"],
            "signature_valid": signature_valid,
        }
        self.nodes[cid] = node
        self.messages[cid] = copy.deepcopy(message)
        return cid

    def get_node(self, cid: str) -> dict[str, Any]:
        return self.nodes[cid]

    def get_lineage(self, cid: str) -> list[dict[str, Any]]:
        if cid not in self.nodes:
            raise AuditDAGError("unknown cid")
        lineage: list[dict[str, Any]] = []
        seen: set[str] = set()

        def visit(current: str) -> None:
            if current in seen:
                return
            seen.add(current)
            for parent in self.nodes[current]["parents"]:
                if parent in self.nodes:
                    visit(parent)
            lineage.append(self.nodes[current])

        visit(cid)
        return lineage

    def detect_missing_parent(self) -> list[tuple[str, str]]:
        missing = []
        for cid, node in self.nodes.items():
            for parent in node["parents"]:
                if parent not in self.nodes:
                    missing.append((cid, parent))
        return missing

    def detect_tampering(self) -> list[str]:
        changed = []
        for cid, message in self.messages.items():
            if sha256_cid(message) != cid:
                changed.append(cid)
        return changed

    def verify_dag_integrity(self) -> bool:
        missing = self.detect_missing_parent()
        tampered = self.detect_tampering()
        invalid_sig = [cid for cid, node in self.nodes.items() if not node.get("signature_valid")]
        if missing or tampered or invalid_sig:
            raise AuditDAGError(f"DAG integrity failed: missing={missing}, tampered={tampered}, invalid_sig={invalid_sig}")
        return True

    def export_jsonl(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            for node in self.nodes.values():
                fh.write(json.dumps(node, sort_keys=True) + "\n")
