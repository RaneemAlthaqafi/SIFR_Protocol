"""did:web resolver.

Implements https://w3c-ccg.github.io/did-method-web/. The host portion of the
DID may contain a percent-encoded colon (`%3A`) to indicate a port; subsequent
colons indicate path segments that resolve as `/<segment>/<.../>did.json`.
"""
from __future__ import annotations

import urllib.parse
from typing import Optional

import httpx

from . import DidDocument, DidResolutionError, DidResolver, parse_did_document

__all__ = ["DidWebResolver"]


class DidWebResolver(DidResolver):
    def __init__(
        self,
        *,
        client: Optional[httpx.Client] = None,
        scheme: str = "https",
    ) -> None:
        self._client = client or httpx.Client(timeout=10.0)
        self._scheme = scheme
        self._cache: dict[str, DidDocument] = {}

    def _did_to_url(self, did: str) -> str:
        if not did.startswith("did:web:"):
            raise DidResolutionError(f"not a did:web identifier: {did}")
        rest = did[len("did:web:") :]
        parts = rest.split(":")
        host = urllib.parse.unquote(parts[0])
        if len(parts) == 1:
            path = "/.well-known/did.json"
        else:
            path = "/" + "/".join(parts[1:]) + "/did.json"
        return f"{self._scheme}://{host}{path}"

    def resolve_document(self, did: str) -> DidDocument:
        if did in self._cache:
            return self._cache[did]
        url = self._did_to_url(did)
        try:
            resp = self._client.get(url)
        except httpx.HTTPError as exc:
            raise DidResolutionError(f"HTTP error fetching {url}: {exc}") from exc
        if resp.status_code != 200:
            raise DidResolutionError(
                f"DID document not found at {url}: HTTP {resp.status_code}"
            )
        try:
            raw = resp.json()
        except Exception as exc:
            raise DidResolutionError(f"DID document at {url} is not valid JSON") from exc
        doc = parse_did_document(raw)
        if doc.id != did:
            raise DidResolutionError(
                f"DID document at {url} declares id={doc.id!r}, expected {did!r}"
            )
        self._cache[did] = doc
        return doc
