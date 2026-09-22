"""Device-signed HTTP client for the tracker's Connect device endpoints.

Every call here is authenticated purely by a per-request Ed25519 device proof
(`proof.access_proof_headers`); the tracker holds the Atlas token and relays on
the bound operator's behalf. This client signs the exact path and raw query it
sends, so the proof the tracker reconstructs matches byte-for-byte.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .proof import access_proof_headers
from .store import DeviceCredential

_DEFAULT_TIMEOUT_S = 30
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

FUNNEL_LEADS_PATH = "/api/connect/device/funnel/leads"


class TrackerError(Exception):
    """A tracker call failed. ``retryable`` steers the Connect error mapping."""

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class TrackerAuthError(TrackerError):
    """The device or its bound operator is no longer authorized (401/403)."""


@dataclass
class TrackerClient:
    base_url: str
    credential: DeviceCredential
    timeout_s: int = _DEFAULT_TIMEOUT_S

    def _root(self) -> str:
        return self.base_url.rstrip("/")

    def get_funnel_leads(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, object]:
        """Device work-queue poll: relays the tracker's funnel review overlay.

        Read-only; carries no confirmation. Returns the tracker's JSON body
        (``success, leads, workingLeads, pendingHandoffs, cursor, hasMore,
        nextCursor, capabilities, capabilitiesDeclared``).
        """
        params: list[tuple[str, str]] = [("limit", str(int(limit)))]
        if cursor:
            params.append(("cursor", cursor))
        # Sign the exact query string we send: urlencode with a stable order.
        query = urllib.parse.urlencode(params)
        headers = access_proof_headers(
            self.credential.private_key,
            self.credential.device_id,
            method="GET",
            path=FUNNEL_LEADS_PATH,
            query=query,
            body=b"",
        )
        url = f"{self._root()}{FUNNEL_LEADS_PATH}?{query}"
        return self._request("GET", url, headers=headers, body=None)

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
    ) -> dict[str, object]:
        request = urllib.request.Request(url=url, method=method, data=body)
        for key, value in headers.items():
            request.add_header(key, value)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raw = error.read(_MAX_RESPONSE_BYTES + 1) if error.fp else b""
            detail = _error_detail(raw) or error.reason or "tracker request failed"
            status = int(error.code)
            if status in (401, 403):
                raise TrackerAuthError(detail, status=status, retryable=False) from error
            # 5xx and 429 are transient; other 4xx are caller errors.
            retryable = status >= 500 or status == 429
            raise TrackerError(detail, status=status, retryable=retryable) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            # No HTTP response reached us: the effect is unknown, so retryable.
            raise TrackerError(
                f"tracker unreachable: {error}", status=None, retryable=True
            ) from error
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise TrackerError("tracker response too large", status=None, retryable=False)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise TrackerError("tracker returned invalid JSON", status=None) from error
        if not isinstance(parsed, dict):
            raise TrackerError("tracker returned a non-object body", status=None)
        return parsed


def _error_detail(raw: bytes) -> str | None:
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(parsed, dict):
        for key in ("detail", "error", "message"):
            value = parsed.get(key)
            if isinstance(value, str) and value:
                return value
    return None
