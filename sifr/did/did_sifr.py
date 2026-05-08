"""did:sifr resolver.

A local-only DID method. Documents live as `did:sifr:<name>.json` files in a
configured directory. The method exists for tests and offline scenarios — it
makes no claim of decentralization or W3C compliance. See docs/did_method.md.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import DidDocument, DidResolutionError, DidResolver, parse_did_document

__all__ = ["DidSifrResolver"]


class DidSifrResolver(DidResolver):
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        if not self.root.is_dir():
            raise DidResolutionError(
                f"DID document root is not a directory: {self.root}"
            )
        self._cache: dict[str, DidDocument] = {}

    def resolve_document(self, did: str) -> DidDocument:
        if did in self._cache:
            return self._cache[did]
        if not did.startswith("did:sifr:"):
            raise DidResolutionError(f"not a did:sifr identifier: {did}")
        name = did[len("did:sifr:") :]
        if not name or "/" in name or "\\" in name or ".." in name:
            raise DidResolutionError(f"invalid did:sifr name: {name!r}")
        doc_path = self.root / f"{name}.json"
        if not doc_path.is_file():
            raise DidResolutionError(f"DID document not found: {doc_path}")
        try:
            raw = json.loads(doc_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise DidResolutionError(
                f"DID document at {doc_path} is not valid JSON"
            ) from exc
        doc = parse_did_document(raw)
        if doc.id != did:
            raise DidResolutionError(
                f"DID document at {doc_path} declares id={doc.id!r}, expected {did!r}"
            )
        self._cache[did] = doc
        return doc
