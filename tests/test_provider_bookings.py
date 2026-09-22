"""Money path: lead.estimate-booking and lead.first-clean-booking end to end.

Both bookings ride the shared money seam (mint a single-use device challenge, then
the device-signed booking POST). Exercised through a proof-verifying stub tracker,
parametrized over the two bookings so each capability's media types, tracker path,
and receipt are covered.
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
_START = "2026-02-01T09:00:00Z"
_END = "2026-02-01T10:00:00Z"

_ESTIMATE = {
    "capability_id": capabilities.ESTIMATE_BOOKING_CAPABILITY_ID,
    "input_media_type": capabilities.ESTIMATE_BOOKING_INPUT_MEDIA_TYPE,
    "receipt_media_type": capabilities.ESTIMATE_BOOKING_RECEIPT_MEDIA_TYPE,
    "path_suffix": "/estimate-bookings",
    "receipt": {
        "success": True,
        "contactId": _CONTACT_ID,
        "leadStage": "estimate_booked",
        "status": "estimate_booked",
        "idempotent": False,
    },
}
_FIRST_CLEAN = {
    "capability_id": capabilities.FIRST_CLEAN_BOOKING_CAPABILITY_ID,
    "input_media_type": capabilities.FIRST_CLEAN_BOOKING_INPUT_MEDIA_TYPE,
    "receipt_media_type": capabilities.FIRST_CLEAN_BOOKING_RECEIPT_MEDIA_TYPE,
    "path_suffix": "/first-clean-bookings",
    "receipt": {
        "success": True,
        "contactId": _CONTACT_ID,
        "leadStage": "won",
        "status": "first_clean_booked",
        "idempotent": False,
        "onboardingDraftId": "99999999-9999-4999-8999-999999999999",
    },
}
_BOTH = [
    pytest.param(_ESTIMATE, id="estimate"),
    pytest.param(_FIRST_CLEAN, id="first_clean"),
]


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


def _multipart(request_bytes: bytes, artifact_bytes: bytes, media_type: str) -> tuple[str, bytes]:
    boundary = f"----eomtest{uuid4().hex}"
    b = boundary.encode()
    body = b"".join(
        [
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="request"\r\n',
            b"Content-Type: application/json\r\n\r\n",
            request_bytes + b"\r\n",
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="artifact"\r\n',
            b"Content-Type: " + media_type.encode() + b"\r\n\r\n",
            artifact_bytes + b"\r\n",
            b"--" + b + b"--\r\n",
        ]
    )
    return f"multipart/form-data; boundary={boundary}", body


def _booking_artifact(**overrides) -> bytes:
    payload = {
        "contactId": _CONTACT_ID,
        "scheduledStart": _START,
        "scheduledEnd": _END,
        "idempotencyKey": _IDEMPOTENCY_KEY,
        "confirmationId": _CONFIRMATION_ID,
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def _job_request(
    job_id: str,
    capability_id: str,
    media_type: str,
    artifact: bytes,
    artifact_id: str,
    parameters: dict,
) -> bytes:
    request = {
        "protocol_version": 2,
        "job_id": job_id,
        "capability": {"id": capability_id, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": artifact_id,
                "media_type": media_type,
                "byte_size": len(artifact),
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "display_name": "booking.json",
                "source_app_id": "connect-automate",
            }
        ],
        "parameters": parameters,
    }
    return json.dumps(request).encode()


def _submit(
    provider: EomFunnelProvider,
    case: dict,
    *,
    job_id: str,
    artifact: bytes | None = None,
    artifact_id: str | None = None,
    parameters: dict | None = None,
) -> tuple[int, dict]:
    payload = _booking_artifact() if artifact is None else artifact
    media_type = case["input_media_type"]
    content_type, body = _multipart(
        _job_request(
            job_id,
            case["capability_id"],
            media_type,
            payload,
            artifact_id or str(uuid4()),
            parameters or {},
        ),
        payload,
        media_type,
    )
    request = urllib.request.Request(url=f"{provider.base_url}v2/jobs", method="POST", data=body)
    request.add_header("Authorization", f"Bearer {provider.token}")
    request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _output_json(status: dict, receipt_media_type: str) -> dict:
    output = status["result"]["outputs"][0]
    assert output["media_type"] == receipt_media_type
    return json.loads(base64.b64decode(output["payload_base64"]))


@pytest.mark.parametrize("case", _BOTH)
def test_booking_mints_challenge_and_relays_receipt(wired, case):
    tracker, provider = wired
    code, status = _submit(provider, case, job_id=str(uuid4()))
    assert code == 200, status
    assert status["status"] == "completed"
    assert _output_json(status, case["receipt_media_type"]) == case["receipt"]
    # Exactly one challenge minted, carried into the booking; window/key passed through.
    assert len(tracker.state.minted_challenges) == 1
    sent = tracker.state.booking_requests[-1]
    assert sent["contactId"] == _CONTACT_ID
    assert sent["challengeId"] == tracker.state.minted_challenges[-1]
    assert sent["confirmationId"] == _CONFIRMATION_ID
    assert sent["scheduledStart"] == _START
    assert sent["scheduledEnd"] == _END
    assert sent["idempotencyKey"] == _IDEMPOTENCY_KEY
    assert tracker.state.proof_requests[-1]["method"] == "POST"
    assert tracker.state.proof_requests[-1]["path"].endswith(f"/{_CONTACT_ID}{case['path_suffix']}")


@pytest.mark.parametrize("case", _BOTH)
def test_bad_artifact_is_rejected_before_any_tracker_call(wired, case):
    tracker, provider = wired
    # Missing scheduledEnd -> malformed request -> 400, before minting a challenge.
    incomplete = json.dumps(
        {
            "contactId": _CONTACT_ID,
            "scheduledStart": _START,
            "idempotencyKey": _IDEMPOTENCY_KEY,
            "confirmationId": _CONFIRMATION_ID,
        }
    ).encode()
    code, body = _submit(provider, case, job_id=str(uuid4()), artifact=incomplete)
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []
    assert tracker.state.booking_requests == []


def test_non_uuid_contact_id_is_rejected(wired):
    tracker, provider = wired
    code, body = _submit(
        provider, _ESTIMATE, job_id=str(uuid4()), artifact=_booking_artifact(contactId="../evil")
    )
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []


def test_parameters_are_rejected(wired):
    _tracker, provider = wired
    code, body = _submit(provider, _ESTIMATE, job_id=str(uuid4()), parameters={"limit": 5})
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"


def test_auth_error_maps_to_device_unauthorized(wired):
    tracker, provider = wired
    tracker.set_booking_error(403, {"detail": "operator no longer approver"})
    code, status = _submit(provider, _ESTIMATE, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "DEVICE_UNAUTHORIZED"
    assert status["error"]["retryable"] is False


def test_capability_unavailable_maps_non_retryable(wired):
    tracker, provider = wired
    tracker.set_booking_error(501, {"success": False, "error": "atlas_capability_unavailable"})
    code, status = _submit(provider, _FIRST_CLEAN, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "CAPABILITY_UNAVAILABLE"
    assert status["error"]["retryable"] is False
