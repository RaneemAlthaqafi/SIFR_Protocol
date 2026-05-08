"""Loopback HTTP fixture serving DID documents from an in-memory dict.

Used to exercise DidWebResolver against real HTTP traffic in tests, without
depending on any public DID document.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional


class DidWebFixture:
    MALFORMED = object()  # sentinel: serve invalid JSON
    NOT_JSON = object()  # sentinel: serve non-JSON content

    def __init__(self) -> None:
        self.documents: dict[str, object] = {}
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def host(self) -> str:
        assert self._server is not None
        return f"{self._server.server_address[0]}:{self._server.server_address[1]}"

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.server_address[1]

    def did_for_path(self, path_segments: tuple[str, ...] = ()) -> str:
        # Encode the colon between host and port per did:web spec.
        host_addr, port = self._server.server_address  # type: ignore[union-attr]
        encoded = f"{host_addr}%3A{port}"
        if path_segments:
            return "did:web:" + encoded + ":" + ":".join(path_segments)
        return "did:web:" + encoded

    def serve_document(self, path: str, doc: object) -> None:
        if not path.startswith("/"):
            path = "/" + path
        self.documents[path] = doc

    def start(self) -> None:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                doc = fixture.documents.get(self.path)
                if doc is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                if doc is DidWebFixture.MALFORMED:
                    body = b"{ not valid json"
                elif doc is DidWebFixture.NOT_JSON:
                    body = b"<html>nope</html>"
                else:
                    body = json.dumps(doc).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def __enter__(self) -> "DidWebFixture":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
