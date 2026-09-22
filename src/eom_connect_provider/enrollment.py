"""One-time, office-session enrollment that binds this PC to an operator.

Enrollment is the only step that uses the operator's office session, and it is
used once and never persisted (credential contract, "Acquire"). The provider
generates an Ed25519 keypair locally, proves possession by signing the tracker's
enrollment challenge, and stores only ``{device_id, private_key}``. The public key
and the operator binding live on the tracker; the office bearer is discarded by
the caller afterwards, so no reusable secret is left on the PC.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .proof import b64u
from .store import DeviceCredential, default_store_dir, save_credential
from .tracker_client import TrackerAuthError, TrackerError

_CHALLENGE_PATH = "/api/admin/connect/devices/enrollment-challenge"
_DEVICES_PATH = "/api/admin/connect/devices"
_TIMEOUT_S = 30


def enroll(
    *,
    base_url: str,
    office_bearer: str,
    label: str,
    store_dir: Path | None = None,
    timeout_s: int = _TIMEOUT_S,
) -> DeviceCredential:
    """Enroll this PC and persist the device credential; return it.

    ``office_bearer`` authenticates the enrolling operator's office session for
    these two calls only. The caller is responsible for discarding it afterwards.
    """
    root = base_url.rstrip("/")
    target_dir = store_dir if store_dir is not None else default_store_dir()

    challenge_body = _post_json(
        f"{root}{_CHALLENGE_PATH}",
        bearer=office_bearer,
        payload=None,
        timeout_s=timeout_s,
    )
    challenge = challenge_body.get("challenge")
    if not isinstance(challenge, str) or not challenge:
        raise TrackerError("enrollment challenge missing from tracker response")

    private_key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signature = private_key.sign(challenge.encode("ascii"))

    device_view = _post_json(
        f"{root}{_DEVICES_PATH}",
        bearer=office_bearer,
        payload={
            "label": label,
            "publicKey": b64u(public_raw),
            "challenge": challenge,
            "signature": b64u(signature),
        },
        timeout_s=timeout_s,
    )
    device_id = device_view.get("deviceId")
    if not isinstance(device_id, str) or not device_id:
        raise TrackerError("enrollment response missing deviceId")

    credential = DeviceCredential(device_id=device_id, private_key=private_key)
    save_credential(target_dir, credential)
    return credential


def _post_json(
    url: str,
    *,
    bearer: str,
    payload: dict[str, object] | None,
    timeout_s: int,
) -> dict[str, object]:
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url=url, method="POST", data=body)
    request.add_header("Authorization", f"Bearer {bearer}")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            raw = response.read(1024 * 1024)
    except urllib.error.HTTPError as error:
        detail = _detail(error.read(1024 * 1024) if error.fp else b"") or error.reason
        status = int(error.code)
        if status in (401, 403):
            raise TrackerAuthError(
                f"enrollment not authorized: {detail}", status=status
            ) from error
        raise TrackerError(f"enrollment failed: {detail}", status=status) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise TrackerError(f"tracker unreachable: {error}", retryable=True) from error
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise TrackerError("tracker returned a non-object enrollment body")
    return parsed


def _detail(raw: bytes) -> str | None:
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
