"""Money path: lead.customer-handoff end to end through a proof-verifying stub.

Rides the shared money seam (mint a single-use device challenge, then the
device-signed handoff POST). The customer/site payload is opaque to the provider
(the tracker validates it); the provider only pulls atlasContactId for the path and
carries confirmationId. Covers the 202 Atlas-pending outcome, which must map to a
retryable, uncached result so a re-POST replays the tracker's durable reservation
rather than creating a second Customer/Site.
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
_IDEMPOTENCY_KEY = "44444444-4444-4444-8444-444444444444"

_EXPECTED_RECEIPT = {
    "success": True,
    "idempotent": False,
    "handoff": {
        "atlasContactId": _CONTACT_ID,
        "customerId": 4242,
        "siteId": 7,
        "state": "finalized",
        "atlasHandoffId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    },
}


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
    artifact_type = capabilities.CUSTOMER_HANDOFF_INPUT_MEDIA_TYPE.encode()
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


def _handoff_payload() -> dict:
    return {
        "atlasContactId": _CONTACT_ID,
        "idempotencyKey": _IDEMPOTENCY_KEY,
        "primarySite": {"label": "Main site"},
        "displayName": "Acme LLC",
    }


def _artifact(**overrides) -> bytes:
    payload = {"confirmationId": _CONFIRMATION_ID, "handoff": _handoff_payload()}
    payload.update(overrides)
    return json.dumps(payload).encode()


def _job_request(job_id: str, artifact: bytes, artifact_id: str, parameters: dict) -> bytes:
    request = {
        "protocol_version": 2,
        "job_id": job_id,
        "capability": {"id": capabilities.CUSTOMER_HANDOFF_CAPABILITY_ID, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": artifact_id,
                "media_type": capabilities.CUSTOMER_HANDOFF_INPUT_MEDIA_TYPE,
                "byte_size": len(artifact),
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "display_name": "handoff.json",
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
    assert output["media_type"] == capabilities.CUSTOMER_HANDOFF_RECEIPT_MEDIA_TYPE
    return json.loads(base64.b64decode(output["payload_base64"]))


def test_handoff_mints_challenge_and_relays_receipt(wired):
    tracker, provider = wired
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200, status
    assert status["status"] == "completed"
    assert _output_json(status) == _EXPECTED_RECEIPT
    assert len(tracker.state.minted_challenges) == 1
    sent = tracker.state.handoff_requests[-1]
    assert sent["contactId"] == _CONTACT_ID
    assert sent["challengeId"] == tracker.state.minted_challenges[-1]
    assert sent["confirmationId"] == _CONFIRMATION_ID
    # The opaque office payload flowed through unchanged (atlasContactId + key).
    assert sent["atlasContactId"] == _CONTACT_ID
    assert sent["idempotencyKey"] == _IDEMPOTENCY_KEY
    assert tracker.state.proof_requests[-1]["method"] == "POST"
    assert tracker.state.proof_requests[-1]["path"].endswith(f"/{_CONTACT_ID}/customer-handoffs")


def test_atlas_pending_202_maps_retryable_uncached_then_completes(wired):
    tracker, provider = wired
    tracker.set_handoff_status(202, {"success": False, "handoff": {"status": "atlas_pending"}})
    job_id = str(uuid4())
    artifact_id = str(uuid4())
    code, status = _submit(provider, job_id=job_id, artifact_id=artifact_id)
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "OPERATION_PENDING"
    assert status["error"]["retryable"] is True

    # The tracker finalizes; a re-POST of the SAME job re-attempts (not cached) and
    # completes. A fresh challenge is minted for the re-attempt.
    tracker.set_handoff_status(201)
    code, status = _submit(provider, job_id=job_id, artifact_id=artifact_id)
    assert code == 200, status
    assert status["status"] == "completed"
    assert len(tracker.state.minted_challenges) == 2


def test_bad_artifact_is_rejected_before_any_tracker_call(wired):
    tracker, provider = wired
    # Missing the handoff object -> malformed -> 400, before minting a challenge.
    incomplete = json.dumps({"confirmationId": _CONFIRMATION_ID}).encode()
    code, body = _submit(provider, job_id=str(uuid4()), artifact=incomplete)
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []
    assert tracker.state.handoff_requests == []


def test_non_uuid_atlas_contact_id_is_rejected(wired):
    tracker, provider = wired
    payload = _handoff_payload()
    payload["atlasContactId"] = "../evil"
    code, body = _submit(provider, job_id=str(uuid4()), artifact=_artifact(handoff=payload))
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []


def test_handoff_carrying_device_fields_is_rejected(wired):
    tracker, provider = wired
    # The office payload must not smuggle the provider/operator-supplied device fields.
    payload = _handoff_payload()
    payload["challengeId"] = str(uuid4())
    code, body = _submit(provider, job_id=str(uuid4()), artifact=_artifact(handoff=payload))
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []


def test_auth_error_maps_to_device_unauthorized(wired):
    tracker, provider = wired
    tracker.set_handoff_status(403, {"detail": "operator no longer approver"})
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "DEVICE_UNAUTHORIZED"
    assert status["error"]["retryable"] is False


def test_capability_unavailable_maps_non_retryable(wired):
    tracker, provider = wired
    tracker.set_handoff_status(501, {"success": False, "error": "atlas_capability_unavailable"})
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "CAPABILITY_UNAVAILABLE"
    assert status["error"]["retryable"] is False
