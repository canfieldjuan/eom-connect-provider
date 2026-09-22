"""Money path: lead.mark-working end to end through a proof-verifying stub.

Rides the shared money seam (mint a single-use device challenge, then the
device-signed POST). Optimistic on the lead's state token; a stale token is a 409
the provider maps to a non-retryable STATE_CONFLICT.
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

_CONTACT_ID = "11111111-1111-4111-8111-111111111111"
_CONFIRMATION_ID = "22222222-2222-4222-8222-222222222222"
_STATE_TOKEN = "a" * 64


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


def _multipart(request_bytes: bytes, artifact_bytes: bytes) -> tuple[str, bytes]:
    boundary = f"----eomtest{uuid4().hex}"
    b = boundary.encode()
    artifact_type = capabilities.MARK_WORKING_INPUT_MEDIA_TYPE.encode()
    body = b"".join(
        [
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="request"\r\n',
            b"Content-Type: application/json\r\n\r\n",
            request_bytes + b"\r\n",
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="artifact"\r\n',
            b"Content-Type: " + artifact_type + b"\r\n\r\n",
            artifact_bytes + b"\r\n",
            b"--" + b + b"--\r\n",
        ]
    )
    return f"multipart/form-data; boundary={boundary}", body


def _artifact(**overrides) -> bytes:
    payload = {
        "contactId": _CONTACT_ID,
        "expectedStateToken": _STATE_TOKEN,
        "confirmationId": _CONFIRMATION_ID,
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def _job_request(job_id: str, artifact: bytes, artifact_id: str, parameters: dict) -> bytes:
    request = {
        "protocol_version": 2,
        "job_id": job_id,
        "capability": {"id": capabilities.MARK_WORKING_CAPABILITY_ID, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": artifact_id,
                "media_type": capabilities.MARK_WORKING_INPUT_MEDIA_TYPE,
                "byte_size": len(artifact),
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "display_name": "mark-working.json",
                "source_app_id": "connect-automate",
            }
        ],
        "parameters": parameters,
    }
    return json.dumps(request).encode()


def _submit(
    provider: EomFunnelProvider,
    *,
    job_id: str,
    artifact: bytes | None = None,
    artifact_id: str | None = None,
    parameters: dict | None = None,
) -> tuple[int, dict]:
    payload = _artifact() if artifact is None else artifact
    content_type, body = _multipart(
        _job_request(job_id, payload, artifact_id or str(uuid4()), parameters or {}),
        payload,
    )
    request = urllib.request.Request(url=f"{provider.base_url}v2/jobs", method="POST", data=body)
    request.add_header("Authorization", f"Bearer {provider.token}")
    request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _output_json(status: dict) -> dict:
    output = status["result"]["outputs"][0]
    assert output["media_type"] == capabilities.MARK_WORKING_RECEIPT_MEDIA_TYPE
    return json.loads(base64.b64decode(output["payload_base64"]))


def test_mark_working_mints_challenge_and_relays_receipt(wired):
    tracker, provider = wired
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200, status
    assert status["status"] == "completed"
    receipt = _output_json(status)
    assert receipt["success"] is True
    assert receipt["workingLead"]["contactId"] == _CONTACT_ID
    assert len(tracker.state.minted_challenges) == 1
    sent = tracker.state.working_requests[-1]
    assert sent["contactId"] == _CONTACT_ID
    assert sent["challengeId"] == tracker.state.minted_challenges[-1]
    assert sent["confirmationId"] == _CONFIRMATION_ID
    assert sent["expectedStateToken"] == _STATE_TOKEN
    assert tracker.state.proof_requests[-1]["method"] == "POST"
    assert tracker.state.proof_requests[-1]["path"].endswith(f"/{_CONTACT_ID}/working")


def test_stale_state_token_maps_state_conflict(wired):
    tracker, provider = wired
    tracker.set_working_status(409, {"detail": "lead review state changed"})
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "STATE_CONFLICT"
    assert status["error"]["retryable"] is False


def test_bad_artifact_is_rejected_before_any_tracker_call(wired):
    tracker, provider = wired
    # Missing expectedStateToken -> malformed -> 400, before minting a challenge.
    incomplete = json.dumps(
        {"contactId": _CONTACT_ID, "confirmationId": _CONFIRMATION_ID}
    ).encode()
    code, body = _submit(provider, job_id=str(uuid4()), artifact=incomplete)
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []
    assert tracker.state.working_requests == []


def test_non_uuid_contact_id_is_rejected(wired):
    tracker, provider = wired
    code, body = _submit(provider, job_id=str(uuid4()), artifact=_artifact(contactId="../evil"))
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []


def test_auth_error_maps_to_device_unauthorized(wired):
    tracker, provider = wired
    tracker.set_working_status(403, {"detail": "operator no longer approver"})
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "DEVICE_UNAUTHORIZED"
    assert status["error"]["retryable"] is False
