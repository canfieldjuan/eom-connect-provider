"""A loopback stub of the tracker's device endpoints for tests.

It verifies the device proof and the enrollment challenge signature the same way
the real tracker does (`_connect_device_access_signing_string`,
`require_connect_device`), so a wrong proof fails here exactly as it would in
production. It also lets a test force an error status on the leads read to exercise
the provider's Connect error mapping.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_CONTEXT = "connect-device-access-v1"


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass
class _State:
    public_keys: dict[str, bytes] = field(default_factory=dict)
    queue_body: dict[str, object] = field(default_factory=dict)
    leads_status: int = 200
    leads_error: dict[str, object] | None = None
    challenge: str = "challenge-fixture-token"
    lock: threading.Lock = field(default_factory=threading.Lock)
    proof_requests: list[dict[str, str]] = field(default_factory=list)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.state = _State()


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: int, value: dict[str, object]) -> None:
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def do_POST(self) -> None:
        state = self.server.state
        if self.path == "/api/admin/connect/devices/enrollment-challenge":
            self._read_body()
            self._json(200, {"challenge": state.challenge, "expiresAt": "2026-01-01T00:00:00Z"})
            return
        if self.path == "/api/admin/connect/devices":
            body = json.loads(self._read_body() or b"{}")
            public_raw = _b64u_decode(body["publicKey"])
            try:
                Ed25519PublicKey.from_public_bytes(public_raw).verify(
                    _b64u_decode(body["signature"]), body["challenge"].encode("ascii")
                )
            except (InvalidSignature, KeyError, ValueError):
                self._json(400, {"detail": "enrollment signature invalid"})
                return
            device_id = str(uuid4())
            with state.lock:
                state.public_keys[device_id] = public_raw
            self._json(201, {"deviceId": device_id, "label": body.get("label"), "status": "active"})
            return
        self._json(404, {"detail": "not found"})

    def do_GET(self) -> None:
        state = self.server.state
        path, _, query = self.path.partition("?")
        if path != "/api/connect/device/funnel/leads":
            self._json(404, {"detail": "not found"})
            return
        device_id = self.headers.get("X-Connect-Device", "")
        timestamp = self.headers.get("X-Connect-Timestamp", "")
        signature = self.headers.get("X-Connect-Signature", "")
        with state.lock:
            public_raw = state.public_keys.get(device_id)
            state.proof_requests.append(
                {"device": device_id, "timestamp": timestamp, "query": query}
            )
        if public_raw is None:
            self._json(401, {"detail": "unknown device"})
            return
        signing_string = "\n".join(
            [_CONTEXT, device_id, "GET", path, query, hashlib.sha256(b"").hexdigest(), timestamp]
        ).encode("utf-8")
        try:
            Ed25519PublicKey.from_public_bytes(public_raw).verify(
                _b64u_decode(signature), signing_string
            )
        except (InvalidSignature, ValueError):
            self._json(401, {"detail": "device proof invalid"})
            return
        if state.leads_status != 200:
            self._json(state.leads_status, state.leads_error or {"detail": "forced error"})
            return
        self._json(200, state.queue_body)


@dataclass
class StubTracker:
    server: _Server
    thread: threading.Thread

    @classmethod
    def start(cls) -> StubTracker:
        server = _Server()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return cls(server, thread)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def state(self) -> _State:
        return self.server.state

    def register_public_key(self, device_id: str, public_raw: bytes) -> None:
        with self.state.lock:
            self.state.public_keys[device_id] = public_raw

    def set_queue(self, body: dict[str, object]) -> None:
        with self.state.lock:
            self.state.queue_body = body

    def force_leads_error(self, status: int, error: dict[str, object] | None = None) -> None:
        with self.state.lock:
            self.state.leads_status = status
            self.state.leads_error = error

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
