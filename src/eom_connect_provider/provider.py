"""The local EOM Connect provider: a loopback Connect v2 process on the buyer PC.

The Automate host discovers this provider over loopback and invokes a capability
with a caller-minted stable ``job_id`` (ADR-0005, same-PC placement). Each capability
maps to a tracker device endpoint reached with a per-request Ed25519 device proof; the
tracker holds the Atlas token and relays on the bound operator's behalf. The provider
never holds an Atlas secret and never re-renders from mutable state: a retry replays
the frozen job identity.

Dispatch is registry-driven (``capabilities.REGISTRY``): the same registry backs the
served manifest and the accepted job envelope, so the advertised capability and what
``_validate`` enforces cannot drift. A read (empty artifact, limit/cursor in job
parameters) relays a device-signed GET. A money path (a small vendor JSON artifact,
no parameters, ``confirmation_required``) mints a single-use device challenge, then
makes the device-signed money POST the tracker gates on that challenge plus the
operator's confirmation carried inside the artifact.

Protocol (matching the host's Connect v2 client and the reference provider):
- registration file under ``runtime_dir/local-connect/v2/providers/{id}.json``;
- ``GET /v2/manifest`` -> the capability manifest;
- ``POST /v2/jobs`` (multipart: ``request`` + ``artifact``) -> a terminal job
  status, idempotent by ``job_id`` (409 if the id is reused for other input);
- ``GET /v2/jobs/{job_id}`` -> a stored completed status, else 404.

Jobs are synchronous: the POST returns the terminal status. A completed job is cached
by ``job_id``; a *retryable* failure is not cached, so a re-POST re-attempts against
the tracker rather than replaying a stale error. The tracker's own idempotency (the
draft/booking state machine) makes a re-attempt of a money path safe.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from . import capabilities, tracker_client
from .capabilities import CapabilitySpec
from .tracker_client import TrackerAuthError, TrackerError


class TrackerGateway(Protocol):
    """The tracker device-endpoint calls the provider needs, injected for testability.

    A real ``TrackerClient`` satisfies this structurally; tests pass a client pointed
    at a proof-verifying stub. Keeping the provider on this interface (not the concrete
    client) means the server has no live-tracker dependency of its own.
    """

    def get_funnel_leads(
        self, *, limit: int, cursor: str | None
    ) -> dict[str, object]: ...

    def list_issued_links(
        self, *, limit: int, cursor: str | None
    ) -> dict[str, object]: ...

    def mint_operation_challenge(self) -> dict[str, object]: ...

    def approve_send(
        self, draft_id: str, challenge_id: str, confirmation_id: str
    ) -> dict[str, object]: ...

    def revoke_public_link(
        self, draft_id: str, challenge_id: str, confirmation_id: str
    ) -> dict[str, object]: ...


# Cap the whole multipart body: the largest declared input artifact plus generous
# slack for the request part and MIME framing.
_MAX_REQUEST_BYTES = (
    max(spec.max_input_bytes for spec in capabilities.REGISTRY.values()) + 256 * 1024
)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _uuid4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


@dataclass
class _Stored:
    signature: str
    status: dict[str, object]
    request: dict[str, object]


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, tracker: TrackerGateway) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.instance_id = str(uuid4())
        self.token = secrets.token_urlsafe(32)
        self.tracker = tracker
        self.jobs: dict[str, _Stored] = {}
        self.lock = threading.Lock()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/"

    def manifest(self) -> dict[str, object]:
        return capabilities.manifest(self.instance_id)


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: int, value: dict[str, object]) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        with suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(payload)

    def _error(self, status: int, code: str, message: str, *, retryable: bool = False) -> None:
        self._json(
            status,
            {
                "protocol_version": 2,
                "error": {"code": code, "message": message, "retryable": retryable},
            },
        )

    def _authorized(self) -> bool:
        return secrets.compare_digest(
            self.headers.get("Authorization", ""), f"Bearer {self.server.token}"
        )

    def do_GET(self) -> None:
        if not self._authorized():
            self._error(401, "UNAUTHORIZED", "Provider authorization failed.")
        elif self.path == "/v2/manifest":
            self._json(200, self.server.manifest())
        elif self.path.startswith("/v2/jobs/"):
            with self.server.lock:
                stored = self.server.jobs.get(self.path.removeprefix("/v2/jobs/"))
            if stored is None:
                self._error(404, "JOB_NOT_FOUND", "Job was not found.")
            else:
                self._json(200, stored.status)
        else:
            self._error(404, "NOT_FOUND", "Route was not found.")

    def do_POST(self) -> None:
        if not self._authorized():
            self._error(401, "UNAUTHORIZED", "Provider authorization failed.")
            return
        if self.path != "/v2/jobs":
            self._error(404, "NOT_FOUND", "Route was not found.")
            return
        try:
            request, artifact = self._request_parts()
            spec, job_id, signature = self._validate(request, artifact)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            self._error(400, "INVALID_REQUEST", str(error))
            return

        # Return a cached completed job, or reject a reused id with other input,
        # before touching the tracker.
        with self.server.lock:
            stored = self.server.jobs.get(job_id)
            if stored is not None and stored.signature != signature:
                self._error(409, "JOB_CONFLICT", "Job identity was reused for other input.")
                return
            if stored is not None:
                self._json(200, stored.status)
                return

        status = self._run(spec, request, artifact)

        # Cache only terminal successes: a retryable failure must let a re-POST
        # re-attempt rather than replay a stale error.
        if status["status"] == "completed":
            with self.server.lock:
                stored = self.server.jobs.get(job_id)
                if stored is not None and stored.signature != signature:
                    self._error(409, "JOB_CONFLICT", "Job identity was reused for other input.")
                    return
                if stored is None:
                    self.server.jobs[job_id] = _Stored(signature, status, request)
                else:
                    status = stored.status
        self._json(200, status)

    def _request_parts(self) -> tuple[dict[str, object], bytes]:
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= _MAX_REQUEST_BYTES:
            raise ValueError("Request body size is invalid.")
        content_type = self.headers.get("Content-Type", "")
        header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
        message = BytesParser(policy=default).parsebytes(header + self.rfile.read(length))
        if not message.is_multipart():
            raise ValueError("Request must be multipart/form-data.")
        parts: dict[str, bytes] = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            payload = part.get_payload(decode=True)
            if name not in {"request", "artifact"} or not isinstance(payload, bytes):
                raise ValueError("Multipart request contains an invalid part.")
            if name in parts:
                raise ValueError("Multipart request contains a duplicate part.")
            parts[name] = payload
        if set(parts) != {"request", "artifact"}:
            raise ValueError("Multipart request must contain request and artifact parts.")
        request = json.loads(parts["request"])
        if not isinstance(request, dict):
            raise ValueError("Job request must be an object.")
        return request, parts["artifact"]

    def _validate(
        self, request: dict[str, object], artifact: bytes
    ) -> tuple[CapabilitySpec, str, str]:
        if set(request) != {"protocol_version", "job_id", "capability", "inputs", "parameters"}:
            raise ValueError("Job request shape is invalid.")
        job_id = request["job_id"]
        capability = request["capability"]
        inputs = request["inputs"]
        if (
            request["protocol_version"] != 2
            or not _uuid4(job_id)
            or not isinstance(capability, dict)
            or not isinstance(inputs, list)
            or len(inputs) != 1
            or not isinstance(inputs[0], dict)
        ):
            raise ValueError("Job selection is invalid.")
        # The registry is the single source of truth for what is served and accepted.
        spec = capabilities.REGISTRY.get(capability.get("id"))  # type: ignore[arg-type]
        if spec is None or capability.get("version") != spec.version:
            raise ValueError("Job selection is invalid.")
        artifact_meta = inputs[0]
        if (
            set(artifact_meta)
            != {"artifact_id", "media_type", "byte_size", "sha256", "display_name", "source_app_id"}
            or artifact_meta.get("media_type") != spec.input_media_type
            or artifact_meta.get("byte_size") != len(artifact)
            or artifact_meta.get("sha256") != hashlib.sha256(artifact).hexdigest()
            or len(artifact) > spec.max_input_bytes
        ):
            raise ValueError("Input artifact integrity is invalid.")
        self._validate_envelope(spec, request, artifact)
        signature = hashlib.sha256(
            json.dumps(request, separators=(",", ":"), sort_keys=True).encode() + b"\0" + artifact
        ).hexdigest()
        return spec, str(job_id), signature

    def _validate_envelope(
        self, spec: CapabilitySpec, request: dict[str, object], artifact: bytes
    ) -> None:
        """Per-kind envelope rules, so a malformed job is a 400 before any tracker call."""
        if spec.kind == capabilities.KIND_READ:
            # limit/cursor are job parameters (canonical read convention); the single
            # input artifact carries no body.
            _parse_read_parameters(request["parameters"])
            if len(artifact) != 0:
                raise ValueError("A read carries an empty input artifact.")
        elif spec.kind == capabilities.KIND_MONEY:
            # Money paths declare no parameters and carry a non-empty vendor JSON artifact.
            if request["parameters"] != {}:
                raise ValueError("This capability accepts no parameters.")
            if len(artifact) == 0:
                raise ValueError("A money path requires a non-empty input artifact.")
            _parse_money_artifact(spec.capability_id, artifact)
        else:  # pragma: no cover - the registry only holds known kinds
            raise ValueError("Unknown capability kind.")

    def _run(
        self, spec: CapabilitySpec, request: dict[str, object], artifact: bytes
    ) -> dict[str, object]:
        if spec.kind == capabilities.KIND_READ:
            return self._run_read(spec, request, artifact)
        return self._run_money(spec, request, artifact)

    def _run_read(
        self, spec: CapabilitySpec, request: dict[str, object], artifact: bytes
    ) -> dict[str, object]:
        try:
            limit, cursor = _parse_read_parameters(request["parameters"])
            result = self._dispatch_read(spec, limit, cursor)
            output = json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
            return self._status(spec, request, artifact, result_output=output)
        except ValueError as error:
            return self._status(
                spec, request, artifact, error=("INVALID_REQUEST", str(error), False)
            )
        except TrackerAuthError as error:
            return self._status(
                spec, request, artifact, error=("DEVICE_UNAUTHORIZED", str(error), False)
            )
        except TrackerError as error:
            return self._status(spec, request, artifact, error=_map_tracker_error(error))

    def _dispatch_read(
        self, spec: CapabilitySpec, limit: int, cursor: str | None
    ) -> dict[str, object]:
        """Run one read against its tracker endpoint, chosen by capability id."""
        if spec.capability_id == capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID:
            return self.server.tracker.get_funnel_leads(limit=limit, cursor=cursor)
        if spec.capability_id == capabilities.PUBLIC_LINK_LIST_CAPABILITY_ID:
            return self.server.tracker.list_issued_links(limit=limit, cursor=cursor)
        raise TrackerError(  # pragma: no cover - the registry only holds wired ids
            "no read handler for capability", retryable=False
        )

    def _run_money(
        self, spec: CapabilitySpec, request: dict[str, object], artifact: bytes
    ) -> dict[str, object]:
        try:
            receipt = self._dispatch_money(spec, artifact)
            output = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
            return self._status(spec, request, artifact, result_output=output)
        except TrackerAuthError as error:
            return self._status(
                spec, request, artifact, error=("DEVICE_UNAUTHORIZED", str(error), False)
            )
        except TrackerError as error:
            return self._status(spec, request, artifact, error=_map_tracker_error(error))

    def _dispatch_money(self, spec: CapabilitySpec, artifact: bytes) -> dict[str, object]:
        """Run one money path: mint the single-use challenge, then the money POST.

        The challenge is the shared money seam; the per-capability part is which
        artifact fields to read and which signed tracker call to make.
        """
        parsed = _parse_money_artifact(spec.capability_id, artifact)
        challenge_id = self._mint_challenge()
        if spec.capability_id == capabilities.APPROVE_SEND_CAPABILITY_ID:
            return self.server.tracker.approve_send(
                parsed["draftId"], challenge_id, parsed["confirmationId"]
            )
        if spec.capability_id == capabilities.PUBLIC_LINK_REVOKE_CAPABILITY_ID:
            return self.server.tracker.revoke_public_link(
                parsed["draftId"], challenge_id, parsed["confirmationId"]
            )
        booking_path = _BOOKING_PATHS.get(spec.capability_id)
        if booking_path is not None:
            return self.server.tracker.submit_booking(
                booking_path,
                parsed["contactId"],
                challenge_id,
                parsed["confirmationId"],
                parsed["scheduledStart"],
                parsed["scheduledEnd"],
                parsed["idempotencyKey"],
            )
        if spec.capability_id == capabilities.CUSTOMER_HANDOFF_CAPABILITY_ID:
            return self.server.tracker.submit_customer_handoff(
                parsed["contactId"], challenge_id, parsed["confirmationId"], parsed["handoff"]
            )
        if spec.capability_id == capabilities.MARK_WORKING_CAPABILITY_ID:
            return self.server.tracker.mark_lead_working(
                parsed["contactId"],
                challenge_id,
                parsed["confirmationId"],
                parsed["expectedStateToken"],
            )
        raise TrackerError(  # pragma: no cover - the registry only holds wired ids
            "no money handler for capability", retryable=False
        )

    def _mint_challenge(self) -> str:
        challenge = self.server.tracker.mint_operation_challenge()
        challenge_id = challenge.get("challengeId")
        if not isinstance(challenge_id, str) or not challenge_id:
            raise TrackerError(
                "tracker returned an invalid operation challenge", retryable=False
            )
        return challenge_id

    def _status(
        self,
        spec: CapabilitySpec,
        request: dict[str, object],
        artifact: bytes,
        *,
        result_output: bytes | None = None,
        error: tuple[str, str, bool] | None = None,
    ) -> dict[str, object]:
        artifact_meta = request["inputs"][0]  # type: ignore[index]
        timestamp = _now()
        status: dict[str, object] = {
            "protocol_version": 2,
            "job_id": request["job_id"],
            "capability": {"id": spec.capability_id, "version": spec.version},
            "provider": {"app_id": capabilities.APP_ID, "instance_id": self.server.instance_id},
            "status": "completed" if error is None else "failed",
            "created_at": timestamp,
            "updated_at": timestamp,
            "input_artifacts": [
                {
                    key: artifact_meta[key]  # type: ignore[index]
                    for key in ("artifact_id", "media_type", "byte_size", "sha256")
                }
            ],
        }
        if error is None and result_output is not None:
            status["result"] = {
                "outputs": [
                    {
                        "artifact_id": str(uuid4()),
                        "media_type": spec.produces_media_type,
                        "display_name": spec.output_display_name,
                        "byte_size": len(result_output),
                        "sha256": hashlib.sha256(result_output).hexdigest(),
                        "payload_base64": base64.b64encode(result_output).decode("ascii"),
                    }
                ]
            }
        else:
            code, message, retryable = error  # type: ignore[misc]
            status["error"] = {"code": code, "message": message, "retryable": retryable}
        return status


def _map_tracker_error(error: TrackerError) -> tuple[str, str, bool]:
    """Map a tracker failure to a Connect error (code, message, retryable).

    501 is the tracker's typed "Atlas does not implement this yet" (healthy upstream,
    not a transient outage), so it is non-retryable and distinct from a generic 5xx.
    """
    if error.status == 501:
        return "CAPABILITY_UNAVAILABLE", str(error), False
    if error.status == 202:
        # Accepted but not finalized: the tracker holds a durable reservation. A
        # re-POST replays it (no double effect), so this is retryable and uncached.
        return "OPERATION_PENDING", str(error), True
    if error.status == 409:
        # A definitive state conflict (e.g. a stale optimistic token or an already
        # reserved lead): the same request cannot succeed on retry.
        return "STATE_CONFLICT", str(error), False
    if error.retryable:
        return "TRACKER_UNAVAILABLE", str(error), True
    return "TRACKER_ERROR", str(error), False


def _parse_read_parameters(parameters: object) -> tuple[int, str | None]:
    """Parse a paged read's job parameters ``{"limit"?: int, "cursor"?: str}``.

    Shared by every read capability (review-queue, issued-links): limit/cursor ride in
    the Connect job parameters (canonical read convention), not the input artifact,
    which is empty. Raises ``ValueError`` on a malformed value so the caller maps it to
    a 400.
    """
    if not isinstance(parameters, dict) or set(parameters) - {"limit", "cursor"}:
        raise ValueError("Parameters must be an object with optional limit/cursor.")
    limit = parameters.get("limit", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise ValueError("Parameter limit must be an integer in [1, 200].")
    cursor = parameters.get("cursor")
    if cursor is not None and (not isinstance(cursor, str) or not cursor):
        raise ValueError("Parameter cursor must be a non-empty string when present.")
    return limit, cursor


_BOOKING_PATHS = {
    capabilities.ESTIMATE_BOOKING_CAPABILITY_ID: tracker_client.ESTIMATE_BOOKING_PATH,
    capabilities.FIRST_CLEAN_BOOKING_CAPABILITY_ID: tracker_client.FIRST_CLEAN_BOOKING_PATH,
}


_DRAFT_OPERATIONS = frozenset(
    {
        capabilities.APPROVE_SEND_CAPABILITY_ID,
        capabilities.PUBLIC_LINK_REVOKE_CAPABILITY_ID,
    }
)


def _parse_money_artifact(capability_id: str, artifact: bytes) -> dict[str, object]:
    if capability_id in _DRAFT_OPERATIONS:
        return _parse_draft_artifact(artifact)
    if capability_id in _BOOKING_PATHS:
        return _parse_booking_artifact(artifact)
    if capability_id == capabilities.CUSTOMER_HANDOFF_CAPABILITY_ID:
        return _parse_customer_handoff_artifact(artifact)
    if capability_id == capabilities.MARK_WORKING_CAPABILITY_ID:
        return _parse_mark_working_artifact(artifact)
    raise ValueError("Unsupported money capability.")  # pragma: no cover - registry-gated


def _parse_draft_artifact(artifact: bytes) -> dict[str, str]:
    """Parse a draft-keyed operation's input artifact ``{draftId, confirmationId}``.

    Shared by every draft-keyed operation (approve-send, public-link revoke). Opaque
    vendor JSON, not a Connect envelope. ``draftId`` becomes a URL path segment on the
    tracker (a typed UUID there), so it must be a uuid, which also blocks path
    injection. ``confirmationId`` is the operator's single-use token, carried opaque.
    Raises ``ValueError`` on a malformed value so the caller maps it to a 400.
    """
    try:
        value = json.loads(artifact)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Draft artifact is not valid JSON.") from error
    if not isinstance(value, dict) or set(value) != {"draftId", "confirmationId"}:
        raise ValueError("Draft artifact must be {draftId, confirmationId}.")
    draft_id = value["draftId"]
    confirmation_id = value["confirmationId"]
    if not _is_uuid(draft_id):
        raise ValueError("Draft artifact draftId must be a uuid.")
    if not isinstance(confirmation_id, str) or not 1 <= len(confirmation_id) <= 64:
        raise ValueError("Draft artifact confirmationId must be a 1..64 character string.")
    return {"draftId": draft_id, "confirmationId": confirmation_id}


def _parse_booking_artifact(artifact: bytes) -> dict[str, str]:
    """Parse a booking input artifact
    ``{contactId, scheduledStart, scheduledEnd, idempotencyKey, confirmationId}``.

    Opaque vendor JSON. ``contactId`` becomes a URL path segment on the tracker (a
    typed UUID there), so it must be a uuid, which also blocks path injection.
    ``idempotencyKey`` is a uuid (the tracker's durable idempotency identity). The
    window strings are range-checked here so a clearly-malformed booking is a 400
    before any signed call; the tracker still enforces strict RFC 3339. Raises
    ``ValueError`` on a malformed value so the caller maps it to a 400.
    """
    try:
        value = json.loads(artifact)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Booking artifact is not valid JSON.") from error
    expected = {"contactId", "scheduledStart", "scheduledEnd", "idempotencyKey", "confirmationId"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(
            "Booking artifact must be "
            "{contactId, scheduledStart, scheduledEnd, idempotencyKey, confirmationId}."
        )
    if not _is_uuid(value["contactId"]):
        raise ValueError("Booking contactId must be a uuid.")
    if not _is_uuid(value["idempotencyKey"]):
        raise ValueError("Booking idempotencyKey must be a uuid.")
    for field in ("scheduledStart", "scheduledEnd"):
        window = value[field]
        if not isinstance(window, str) or not 20 <= len(window) <= 64:
            raise ValueError(f"Booking {field} must be an RFC 3339 date-time string.")
    confirmation_id = value["confirmationId"]
    if not isinstance(confirmation_id, str) or not 1 <= len(confirmation_id) <= 64:
        raise ValueError("Booking confirmationId must be a 1..64 character string.")
    return {
        "contactId": value["contactId"],
        "scheduledStart": value["scheduledStart"],
        "scheduledEnd": value["scheduledEnd"],
        "idempotencyKey": value["idempotencyKey"],
        "confirmationId": confirmation_id,
    }


def _parse_customer_handoff_artifact(artifact: bytes) -> dict[str, object]:
    """Parse a customer-handoff input artifact ``{confirmationId, handoff}``.

    ``handoff`` is the opaque office customer/site payload; the provider does not
    validate its schema (the tracker does), it only pulls ``atlasContactId`` for the
    URL path (a uuid there, so this also blocks path injection) and forbids the
    device-only fields the provider itself supplies. ``confirmationId`` is the
    operator's single-use token, carried opaque. Raises ``ValueError`` on a malformed
    value so the caller maps it to a 400.
    """
    try:
        value = json.loads(artifact)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Handoff artifact is not valid JSON.") from error
    if not isinstance(value, dict) or set(value) != {"confirmationId", "handoff"}:
        raise ValueError("Handoff artifact must be {confirmationId, handoff}.")
    confirmation_id = value["confirmationId"]
    if not isinstance(confirmation_id, str) or not 1 <= len(confirmation_id) <= 64:
        raise ValueError("Handoff confirmationId must be a 1..64 character string.")
    handoff = value["handoff"]
    if not isinstance(handoff, dict) or not handoff:
        raise ValueError("Handoff payload must be a non-empty object.")
    if {"challengeId", "confirmationId"} & set(handoff):
        raise ValueError("Handoff payload must not carry challengeId or confirmationId.")
    if not _is_uuid(handoff.get("atlasContactId")):
        raise ValueError("Handoff payload atlasContactId must be a uuid.")
    return {
        "contactId": handoff["atlasContactId"],
        "confirmationId": confirmation_id,
        "handoff": handoff,
    }


def _parse_mark_working_artifact(artifact: bytes) -> dict[str, str]:
    """Parse a mark-working input artifact
    ``{contactId, expectedStateToken, confirmationId}``.

    ``contactId`` becomes a URL path segment on the tracker (a uuid there, so this
    also blocks path injection). ``expectedStateToken`` is the opaque optimistic
    token read from the review queue (the tracker compares it and 409s if stale).
    ``confirmationId`` is the operator's single-use token, carried opaque. Raises
    ``ValueError`` on a malformed value so the caller maps it to a 400.
    """
    try:
        value = json.loads(artifact)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Mark-working artifact is not valid JSON.") from error
    if not isinstance(value, dict) or set(value) != {
        "contactId",
        "expectedStateToken",
        "confirmationId",
    }:
        raise ValueError(
            "Mark-working artifact must be {contactId, expectedStateToken, confirmationId}."
        )
    if not _is_uuid(value["contactId"]):
        raise ValueError("Mark-working contactId must be a uuid.")
    token = value["expectedStateToken"]
    if not isinstance(token, str) or not 1 <= len(token) <= 128:
        raise ValueError("Mark-working expectedStateToken must be a 1..128 character string.")
    confirmation_id = value["confirmationId"]
    if not isinstance(confirmation_id, str) or not 1 <= len(confirmation_id) <= 64:
        raise ValueError("Mark-working confirmationId must be a 1..64 character string.")
    return {
        "contactId": value["contactId"],
        "expectedStateToken": token,
        "confirmationId": confirmation_id,
    }


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


def _write_registration(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4()}.tmp")
    try:
        with temporary.open("xb") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@dataclass
class EomFunnelProvider:
    server: _Server
    thread: threading.Thread
    registration_path: Path

    @classmethod
    def start(cls, runtime_dir: Path, tracker: TrackerGateway) -> EomFunnelProvider:
        providers = runtime_dir / "local-connect" / "v2" / "providers"
        for directory in (runtime_dir, runtime_dir / "local-connect", providers.parent, providers):
            _private_directory(directory)
        server = _Server(tracker)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        registration_path = providers / f"{server.instance_id}.json"
        try:
            _write_registration(
                registration_path,
                {
                    "protocol_version": 2,
                    "instance_id": server.instance_id,
                    "app_id": capabilities.APP_ID,
                    "pid": os.getpid(),
                    "started_at": _now(),
                    "transport": {"kind": "http-loopback-v2", "base_url": server.base_url},
                    "auth": {"scheme": "bearer", "token": server.token},
                },
            )
        except BaseException:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            raise
        return cls(server, thread, registration_path)

    @property
    def instance_id(self) -> str:
        return self.server.instance_id

    @property
    def base_url(self) -> str:
        return self.server.base_url

    @property
    def token(self) -> str:
        return self.server.token

    def stop(self) -> None:
        self.registration_path.unlink(missing_ok=True)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
