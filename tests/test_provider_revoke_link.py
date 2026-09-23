"""Money path: onboarding.public-link.revoke end to end through a proof-verifying stub.

The second draft-keyed operation after approve-send: it rides the shared money seam
(mint a single-use device challenge, then the device-signed POST) and the shared
draft artifact parser. A completed link cannot be revoked (tracker 409), which must
map to a non-retryable STATE_CONFLICT.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from stub_tracker import StubTracker

from eom_connect_provider import capabilities, store
from eom_connect_provider.provider import EomFunnelProvider
from eom_connect_provider.tracker_client import TrackerClient

_DRAFT_ID = "11111111-1111-4111-8111-111111111111"
_CONFIRMATION_ID = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def wired(tmp_path):
    tracker = StubTracker.start()
    private_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    tracker.register_public_key(
        device_id, private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    client = TrackerClient(
        tracker.base_url, store.DeviceCredential(device_id=device_id, private_key=private_key)
    )
    provider = EomFunnelProvider.start(tmp_path / "runtime", client)
    try:
        yield tracker, provider
    finally:
        provider.stop()
        tracker.stop()


def _artifact(draft_id: str = _DRAFT_ID, confirmation_id: str = _CONFIRMATION_ID) -> bytes:
    return json.dumps({"draftId": draft_id, "confirmationId": confirmation_id}).encode()


def _submit(provider: EomFunnelProvider, *, artifact: bytes | None = None) -> tuple[int, dict]:
    payload = _artifact() if artifact is None else artifact
    media_type = capabilities.PUBLIC_LINK_REVOKE_INPUT_MEDIA_TYPE
    request = {
        "protocol_version": 2,
        "job_id": str(uuid4()),
        "capability": {"id": capabilities.PUBLIC_LINK_REVOKE_CAPABILITY_ID, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": str(uuid4()),
                "media_type": media_type,
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "display_name": "revocation.json",
                "source_app_id": "connect-automate",
            }
        ],
        "parameters": {},
    }
    boundary = f"----eomtest{uuid4().hex}"
    b = boundary.encode()
    body = b"".join(
        [
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="request"\r\n',
            b"Content-Type: application/json\r\n\r\n",
            json.dumps(request).encode() + b"\r\n",
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="artifact"\r\n',
            b"Content-Type: " + media_type.encode() + b"\r\n\r\n",
            payload + b"\r\n",
            b"--" + b + b"--\r\n",
        ]
    )
    http = urllib.request.Request(url=f"{provider.base_url}v2/jobs", method="POST", data=body)
    http.add_header("Authorization", f"Bearer {provider.token}")
    http.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(http, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_revoke_mints_challenge_and_relays_receipt(wired):
    tracker, provider = wired
    code, status = _submit(provider)
    assert code == 200, status
    assert status["status"] == "completed"
    output = status["result"]["outputs"][0]
    assert output["media_type"] == capabilities.PUBLIC_LINK_REVOKE_RECEIPT_MEDIA_TYPE
    assert json.loads(base64.b64decode(output["payload_base64"])) == {
        "success": True,
        "draftId": _DRAFT_ID,
        "status": "revoked",
        "idempotent": False,
    }
    assert len(tracker.state.minted_challenges) == 1
    sent = tracker.state.revoke_requests[-1]
    assert sent["draftId"] == _DRAFT_ID
    assert sent["challengeId"] == tracker.state.minted_challenges[-1]
    assert sent["confirmationId"] == _CONFIRMATION_ID
    assert tracker.state.proof_requests[-1]["path"].endswith(f"/{_DRAFT_ID}/revoke-link")
    # It is a distinct operation from approve-send: nothing reached that endpoint.
    assert tracker.state.approve_send_requests == []


def test_completed_link_conflict_maps_to_state_conflict(wired):
    tracker, provider = wired
    tracker.set_revoke_status(409, {"detail": "a completed link cannot be revoked"})
    code, status = _submit(provider)
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "STATE_CONFLICT"
    assert status["error"]["retryable"] is False


def test_bad_artifact_is_rejected_before_any_tracker_call(wired):
    tracker, provider = wired
    code, body = _submit(provider, artifact=json.dumps({"draftId": _DRAFT_ID}).encode())
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []
    assert tracker.state.revoke_requests == []


def test_non_uuid_draft_id_is_rejected(wired):
    tracker, provider = wired
    code, body = _submit(provider, artifact=_artifact(draft_id="../evil"))
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []


def test_auth_error_maps_to_device_unauthorized(wired):
    tracker, provider = wired
    tracker.set_revoke_status(403, {"detail": "operator no longer approver"})
    code, status = _submit(provider)
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "DEVICE_UNAUTHORIZED"
    assert status["error"]["retryable"] is False
