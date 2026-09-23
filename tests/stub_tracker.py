"""A loopback stub of the tracker's device endpoints for tests.

It verifies the device proof and the enrollment challenge signature the same way
the real tracker does (`_connect_device_access_signing_string`,
`require_connect_device`), so a wrong proof fails here exactly as it would in
production. The device proof is rebuilt through one shared helper for both GET reads
and POST money paths (method, path, raw query, and body hash), matching the tracker's
single canonical signing string. Tests can force an error status on the leads read or
the approve-send money path to exercise the provider's Connect error mapping.
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

_APPROVE_SEND_PREFIX = "/api/connect/device/funnel/onboarding-drafts/"
_APPROVE_SEND_SUFFIX = "/approve-send"
_REVOKE_LINK_SUFFIX = "/revoke-link"

_LEADS_PREFIX = "/api/connect/device/funnel/leads/"
_ESTIMATE_BOOKING_SUFFIX = "/estimate-bookings"
_FIRST_CLEAN_BOOKING_SUFFIX = "/first-clean-bookings"
_CUSTOMER_HANDOFF_SUFFIX = "/customer-handoffs"
_MARK_WORKING_SUFFIX = "/working"


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _booking_receipt(contact_id: str, kind: str, *, idempotent: bool) -> dict[str, object]:
    if kind == "estimate":
        return {
            "success": True,
            "contactId": contact_id,
            "leadStage": "estimate_booked",
            "status": "estimate_booked",
            "idempotent": idempotent,
        }
    return {
        "success": True,
        "contactId": contact_id,
        "leadStage": "won",
        "status": "first_clean_booked",
        "idempotent": idempotent,
        "onboardingDraftId": "99999999-9999-4999-8999-999999999999",
    }


def _handoff_receipt(contact_id: str, *, idempotent: bool) -> dict[str, object]:
    return {
        "success": True,
        "idempotent": idempotent,
        "handoff": {
            "atlasContactId": contact_id,
            "customerId": 4242,
            "siteId": 7,
            "state": "finalized",
            "atlasHandoffId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        },
    }


def _working_receipt(contact_id: str) -> dict[str, object]:
    return {
        "success": True,
        "workingLead": {
            "contactId": contact_id,
            "markedAt": "2026-09-17T12:20:00Z",
            "markedByEmployeeId": 42,
            "stateToken": "b" * 64,
        },
    }


@dataclass
class _State:
    public_keys: dict[str, bytes] = field(default_factory=dict)
    queue_body: dict[str, object] = field(default_factory=dict)
    issued_links_body: dict[str, object] = field(default_factory=dict)
    leads_status: int = 200
    leads_error: dict[str, object] | None = None
    approve_send_status: int = 201
    approve_send_error: dict[str, object] | None = None
    revoke_status: int = 201
    revoke_error: dict[str, object] | None = None
    revoke_requests: list[dict[str, object]] = field(default_factory=list)
    booking_status: int = 201
    booking_error: dict[str, object] | None = None
    handoff_status: int = 201
    handoff_error: dict[str, object] | None = None
    working_status: int = 200
    working_error: dict[str, object] | None = None
    challenge: str = "challenge-fixture-token"
    lock: threading.Lock = field(default_factory=threading.Lock)
    proof_requests: list[dict[str, str]] = field(default_factory=list)
    minted_challenges: list[str] = field(default_factory=list)
    approve_send_requests: list[dict[str, object]] = field(default_factory=list)
    booking_requests: list[dict[str, object]] = field(default_factory=list)
    handoff_requests: list[dict[str, object]] = field(default_factory=list)
    working_requests: list[dict[str, object]] = field(default_factory=list)


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

    def _verify_proof(self, method: str, path: str, query: str, body: bytes) -> str | None:
        """Rebuild and verify the device access proof; on failure send a 401 and
        return None. Records the request for test assertions either way."""
        state = self.server.state
        device_id = self.headers.get("X-Connect-Device", "")
        timestamp = self.headers.get("X-Connect-Timestamp", "")
        signature = self.headers.get("X-Connect-Signature", "")
        with state.lock:
            public_raw = state.public_keys.get(device_id)
            state.proof_requests.append(
                {
                    "device": device_id,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "query": query,
                }
            )
        if public_raw is None:
            self._json(401, {"detail": "unknown device"})
            return None
        signing_string = "\n".join(
            [_CONTEXT, device_id, method, path, query, hashlib.sha256(body).hexdigest(), timestamp]
        ).encode("utf-8")
        try:
            Ed25519PublicKey.from_public_bytes(public_raw).verify(
                _b64u_decode(signature), signing_string
            )
        except (InvalidSignature, ValueError):
            self._json(401, {"detail": "device proof invalid"})
            return None
        return device_id

    def do_POST(self) -> None:
        state = self.server.state
        path, _, query = self.path.partition("?")
        body = self._read_body()

        if path == "/api/admin/connect/devices/enrollment-challenge":
            self._json(200, {"challenge": state.challenge, "expiresAt": "2026-01-01T00:00:00Z"})
            return
        if path == "/api/admin/connect/devices":
            enrollment = json.loads(body or b"{}")
            public_raw = _b64u_decode(enrollment["publicKey"])
            try:
                Ed25519PublicKey.from_public_bytes(public_raw).verify(
                    _b64u_decode(enrollment["signature"]), enrollment["challenge"].encode("ascii")
                )
            except (InvalidSignature, KeyError, ValueError):
                self._json(400, {"detail": "enrollment signature invalid"})
                return
            device_id = str(uuid4())
            with state.lock:
                state.public_keys[device_id] = public_raw
            self._json(
                201, {"deviceId": device_id, "label": enrollment.get("label"), "status": "active"}
            )
            return
        if path == "/api/connect/device/operations/challenge":
            if self._verify_proof("POST", path, query, body) is None:
                return
            challenge_id = str(uuid4())
            with state.lock:
                state.minted_challenges.append(challenge_id)
            self._json(201, {"challengeId": challenge_id, "expiresAt": "2026-01-01T00:00:00Z"})
            return
        if path.startswith(_APPROVE_SEND_PREFIX) and path.endswith(_APPROVE_SEND_SUFFIX):
            draft_id = path[len(_APPROVE_SEND_PREFIX) : -len(_APPROVE_SEND_SUFFIX)]
            if self._verify_proof("POST", path, query, body) is None:
                return
            try:
                parsed = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"detail": "approve-send body invalid"})
                return
            with state.lock:
                state.approve_send_requests.append(
                    {
                        "draftId": draft_id,
                        "challengeId": parsed.get("challengeId"),
                        "confirmationId": parsed.get("confirmationId"),
                    }
                )
                status = state.approve_send_status
                error = state.approve_send_error
            if status not in (200, 201):
                self._json(status, error or {"detail": "forced error"})
                return
            self._json(
                status,
                {
                    "success": True,
                    "draftId": draft_id,
                    "status": "sent",
                    "sentAt": "2026-01-01T00:00:00Z",
                    "idempotent": status == 200,
                },
            )
            return
        if path.startswith(_APPROVE_SEND_PREFIX) and path.endswith(_REVOKE_LINK_SUFFIX):
            draft_id = path[len(_APPROVE_SEND_PREFIX) : -len(_REVOKE_LINK_SUFFIX)]
            if self._verify_proof("POST", path, query, body) is None:
                return
            try:
                parsed = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"detail": "revoke-link body invalid"})
                return
            with state.lock:
                state.revoke_requests.append(
                    {
                        "draftId": draft_id,
                        "challengeId": parsed.get("challengeId"),
                        "confirmationId": parsed.get("confirmationId"),
                    }
                )
                status = state.revoke_status
                error = state.revoke_error
            if status not in (200, 201):
                self._json(status, error or {"detail": "forced error"})
                return
            self._json(
                status,
                {
                    "success": True,
                    "draftId": draft_id,
                    "status": "revoked",
                    "idempotent": status == 200,
                },
            )
            return
        booking = self._match_booking(path)
        if booking is not None:
            contact_id, kind = booking
            if self._verify_proof("POST", path, query, body) is None:
                return
            try:
                parsed = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"detail": "booking body invalid"})
                return
            with state.lock:
                state.booking_requests.append(
                    {
                        "contactId": contact_id,
                        "kind": kind,
                        "challengeId": parsed.get("challengeId"),
                        "confirmationId": parsed.get("confirmationId"),
                        "scheduledStart": parsed.get("scheduledStart"),
                        "scheduledEnd": parsed.get("scheduledEnd"),
                        "idempotencyKey": parsed.get("idempotencyKey"),
                    }
                )
                status = state.booking_status
                error = state.booking_error
            if status not in (200, 201):
                self._json(status, error or {"detail": "forced error"})
                return
            self._json(status, _booking_receipt(contact_id, kind, idempotent=status == 200))
            return
        if path.startswith(_LEADS_PREFIX) and path.endswith(_CUSTOMER_HANDOFF_SUFFIX):
            contact_id = path[len(_LEADS_PREFIX) : -len(_CUSTOMER_HANDOFF_SUFFIX)]
            if self._verify_proof("POST", path, query, body) is None:
                return
            try:
                parsed = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"detail": "handoff body invalid"})
                return
            with state.lock:
                state.handoff_requests.append(
                    {
                        "contactId": contact_id,
                        "challengeId": parsed.get("challengeId"),
                        "confirmationId": parsed.get("confirmationId"),
                        "atlasContactId": parsed.get("atlasContactId"),
                        "idempotencyKey": parsed.get("idempotencyKey"),
                    }
                )
                status = state.handoff_status
                error = state.handoff_error
            if status not in (200, 201):
                # Includes forced 202 (Atlas pending): the provider maps 202 to a
                # retryable pending outcome, so the body is not consumed there.
                self._json(status, error or {"detail": "forced error"})
                return
            self._json(status, _handoff_receipt(contact_id, idempotent=status == 200))
            return
        if path.startswith(_LEADS_PREFIX) and path.endswith(_MARK_WORKING_SUFFIX):
            contact_id = path[len(_LEADS_PREFIX) : -len(_MARK_WORKING_SUFFIX)]
            if self._verify_proof("POST", path, query, body) is None:
                return
            try:
                parsed = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"detail": "working body invalid"})
                return
            with state.lock:
                state.working_requests.append(
                    {
                        "contactId": contact_id,
                        "challengeId": parsed.get("challengeId"),
                        "confirmationId": parsed.get("confirmationId"),
                        "expectedStateToken": parsed.get("expectedStateToken"),
                    }
                )
                status = state.working_status
                error = state.working_error
            if status not in (200, 201):
                self._json(status, error or {"detail": "forced error"})
                return
            self._json(status, _working_receipt(contact_id))
            return
        self._json(404, {"detail": "not found"})

    @staticmethod
    def _match_booking(path: str) -> tuple[str, str] | None:
        if not path.startswith(_LEADS_PREFIX):
            return None
        for suffix, kind in (
            (_ESTIMATE_BOOKING_SUFFIX, "estimate"),
            (_FIRST_CLEAN_BOOKING_SUFFIX, "first_clean"),
        ):
            if path.endswith(suffix):
                return path[len(_LEADS_PREFIX) : -len(suffix)], kind
        return None

    def do_GET(self) -> None:
        state = self.server.state
        path, _, query = self.path.partition("?")
        if path == "/api/connect/device/funnel/leads":
            if self._verify_proof("GET", path, query, b"") is None:
                return
            if state.leads_status != 200:
                self._json(state.leads_status, state.leads_error or {"detail": "forced error"})
                return
            self._json(200, state.queue_body)
            return
        if path == "/api/connect/device/funnel/public-onboarding/issued-links":
            if self._verify_proof("GET", path, query, b"") is None:
                return
            self._json(200, state.issued_links_body)
            return
        self._json(404, {"detail": "not found"})


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

    def set_issued_links(self, body: dict[str, object]) -> None:
        with self.state.lock:
            self.state.issued_links_body = body

    def force_leads_error(self, status: int, error: dict[str, object] | None = None) -> None:
        with self.state.lock:
            self.state.leads_status = status
            self.state.leads_error = error

    def set_approve_send_error(
        self, status: int, error: dict[str, object] | None = None
    ) -> None:
        with self.state.lock:
            self.state.approve_send_status = status
            self.state.approve_send_error = error

    def set_revoke_status(self, status: int, error: dict[str, object] | None = None) -> None:
        with self.state.lock:
            self.state.revoke_status = status
            self.state.revoke_error = error

    def set_booking_error(self, status: int, error: dict[str, object] | None = None) -> None:
        with self.state.lock:
            self.state.booking_status = status
            self.state.booking_error = error

    def set_handoff_status(self, status: int, error: dict[str, object] | None = None) -> None:
        with self.state.lock:
            self.state.handoff_status = status
            self.state.handoff_error = error

    def set_working_status(self, status: int, error: dict[str, object] | None = None) -> None:
        with self.state.lock:
            self.state.working_status = status
            self.state.working_error = error

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
