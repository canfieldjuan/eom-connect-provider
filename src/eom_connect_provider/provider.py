"""The local EOM Connect provider: a loopback Connect v2 process on the buyer PC.

The Automate host discovers this provider over loopback and invokes a capability
with a caller-minted stable ``job_id`` (ADR-0005, same-PC placement). For the
funnel review-queue read the provider signs a per-request Ed25519 device proof and
calls the tracker's device endpoint, which holds the Atlas token and relays. The
provider never holds an Atlas secret and never re-renders from mutable state: a
retry replays the frozen job identity.

Protocol (matching the host's Connect v2 client and the reference provider):
- registration file under ``runtime_dir/local-connect/v2/providers/{id}.json``;
- ``GET /v2/manifest`` -> the capability manifest;
- ``POST /v2/jobs`` (multipart: ``request`` + ``artifact``) -> a terminal job
  status, idempotent by ``job_id`` (409 if the id is reused for other input);
- ``GET /v2/jobs/{job_id}`` -> a stored completed status, else 404.

Read jobs are synchronous: the POST returns the terminal status. A completed read
is cached by ``job_id``; a *retryable* failure is not cached, so a re-POST
re-attempts against the tracker rather than replaying a stale error.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID, uuid4

from . import capabilities
from .tracker_client import TrackerAuthError, TrackerError

# A callable that performs the read: (limit, cursor) -> the tracker's queue dict.
# Injected so the server is testable without a live tracker; production wires it
# to a TrackerClient.
LeadFetcher = Callable[[int, str | None], dict[str, object]]

# Cap the whole multipart body: the largest declared input artifact plus generous
# slack for the request part and MIME framing.
_MAX_REQUEST_BYTES = capabilities.READ_MAX_INPUT_BYTES + 256 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _uuid4(value: str) -> bool:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return parsed.version == 4 and str(parsed) == value


@dataclass
class _Stored:
    signature: str
    status: dict[str, object]
    request: dict[str, object]


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, fetch_leads: LeadFetcher) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.instance_id = str(uuid4())
        self.token = secrets.token_urlsafe(32)
        self.fetch_leads = fetch_leads
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
            job_id, signature = self._validate(request, artifact)
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

        status = self._run_read(request, artifact)

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

    def _validate(self, request: dict[str, object], artifact: bytes) -> tuple[str, str]:
        if set(request) != {"protocol_version", "job_id", "capability", "inputs", "parameters"}:
            raise ValueError("Job request shape is invalid.")
        job_id = request["job_id"]
        capability = request["capability"]
        inputs = request["inputs"]
        if (
            request["protocol_version"] != 2
            or not isinstance(job_id, str)
            or not _uuid4(job_id)
            or not isinstance(capability, dict)
            or capability.get("id") != capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID
            or capability.get("version") != "1.0"
            or not isinstance(inputs, list)
            or len(inputs) != 1
            or not isinstance(inputs[0], dict)
        ):
            raise ValueError("Job selection is invalid.")
        # limit/cursor are job parameters (canonical read convention); validate them
        # here so a bad parameter is a 400, not a failed job.
        _parse_review_queue_parameters(request["parameters"])
        artifact_meta = inputs[0]
        # The read carries no body: the query lives in parameters, so the single
        # input artifact must be an empty application/json artifact.
        if (
            set(artifact_meta)
            != {"artifact_id", "media_type", "byte_size", "sha256", "display_name", "source_app_id"}
            or artifact_meta.get("media_type") != "application/json"
            or artifact_meta.get("byte_size") != len(artifact)
            or artifact_meta.get("sha256") != hashlib.sha256(artifact).hexdigest()
            or len(artifact) != 0
        ):
            raise ValueError("Input artifact integrity is invalid.")
        signature = hashlib.sha256(
            json.dumps(request, separators=(",", ":"), sort_keys=True).encode() + b"\0" + artifact
        ).hexdigest()
        return job_id, signature

    def _run_read(self, request: dict[str, object], artifact: bytes) -> dict[str, object]:
        try:
            limit, cursor = _parse_review_queue_parameters(request["parameters"])
            queue = self.server.fetch_leads(limit, cursor)
            output = json.dumps(queue, separators=(",", ":"), sort_keys=True).encode()
            return self._status(request, artifact, result_output=output)
        except ValueError as error:
            return self._status(
                request, artifact, error=("INVALID_REQUEST", str(error), False)
            )
        except TrackerAuthError as error:
            return self._status(
                request, artifact, error=("DEVICE_UNAUTHORIZED", str(error), False)
            )
        except TrackerError as error:
            code = "TRACKER_UNAVAILABLE" if error.retryable else "TRACKER_ERROR"
            return self._status(
                request, artifact, error=(code, str(error), error.retryable)
            )

    def _status(
        self,
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
            "capability": {
                "id": capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID,
                "version": "1.0",
            },
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
                        "media_type": capabilities.REVIEW_QUEUE_MEDIA_TYPE,
                        "display_name": "funnel-review-queue.json",
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


def _parse_review_queue_parameters(parameters: object) -> tuple[int, str | None]:
    """Parse the review-queue job parameters ``{"limit"?: int, "cursor"?: str}``.

    limit/cursor ride in the Connect job parameters (canonical read convention), not
    the input artifact, which is empty. Raises ``ValueError`` on a malformed value so
    the caller maps it to a 400.
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
    def start(cls, runtime_dir: Path, fetch_leads: LeadFetcher) -> EomFunnelProvider:
        providers = runtime_dir / "local-connect" / "v2" / "providers"
        for directory in (runtime_dir, runtime_dir / "local-connect", providers.parent, providers):
            _private_directory(directory)
        server = _Server(fetch_leads)
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
