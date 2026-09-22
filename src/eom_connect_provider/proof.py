"""Per-request Ed25519 device proof, byte-identical to the tracker's verifier.

The tracker authenticates a device with a DPoP-style per-request proof rather than
a stored bearer (see `require_connect_device` and
`_connect_device_access_signing_string` in the companion tracker
`backend/time_tracker_api.py`). This module reconstructs the exact same canonical
signing string and header encoding so a proof this provider mints verifies there,
and no Atlas secret is ever needed on the PC.

The canonical string binds a fixed context tag, the device id, the HTTP method,
the request path, the raw query string, the SHA-256 of the body, and a unix
timestamp, newline-delimited. Binding the method, target, and body means a
captured proof cannot be replayed against a different call; the tracker's
freshness window (default 120s) bounds replay against the same call.
"""

from __future__ import annotations

import base64
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Must match the tracker's _CONNECT_DEVICE_ACCESS_PROOF_CONTEXT exactly; the tag
# keeps this proof disjoint from the enrollment-challenge signature.
ACCESS_PROOF_CONTEXT = "connect-device-access-v1"

DEVICE_HEADER = "X-Connect-Device"
TIMESTAMP_HEADER = "X-Connect-Timestamp"
SIGNATURE_HEADER = "X-Connect-Signature"


def b64u(raw: bytes) -> str:
    """URL-safe base64 without padding, matching the tracker's `_b64u`."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def access_signing_string(
    *,
    device_id: str,
    method: str,
    path: str,
    query: str,
    body: bytes,
    timestamp: int,
) -> bytes:
    """Rebuild the tracker's canonical device-access signing string."""
    return "\n".join(
        [
            ACCESS_PROOF_CONTEXT,
            device_id,
            method.upper(),
            path,
            query,
            hashlib.sha256(body).hexdigest(),
            str(timestamp),
        ]
    ).encode("utf-8")


def access_proof_headers(
    private_key: Ed25519PrivateKey,
    device_id: str,
    *,
    method: str,
    path: str,
    query: str = "",
    body: bytes = b"",
    timestamp: int | None = None,
) -> dict[str, str]:
    """Sign one request and return the three proof headers the tracker expects.

    ``path`` is the request path exactly as it will be sent (no query), ``query``
    is the raw query string without the leading ``?`` (empty when there is none).
    The tracker recomputes the same string and verifies it against the device's
    stored public key.
    """
    issued_at = int(time.time()) if timestamp is None else int(timestamp)
    signing_string = access_signing_string(
        device_id=device_id,
        method=method,
        path=path,
        query=query,
        body=body,
        timestamp=issued_at,
    )
    signature = private_key.sign(signing_string)
    return {
        DEVICE_HEADER: device_id,
        TIMESTAMP_HEADER: str(issued_at),
        SIGNATURE_HEADER: b64u(signature),
    }
