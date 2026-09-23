"""Money paths: lead.lost and lead.reopen end to end through a proof-verifying stub.

Both ride the shared money seam (mint a single-use device challenge, then the
device-signed POST). The tracker binds the operator's confirmation to the contact and
idempotency key (and, for lost, the reason code), so those fields must reach it exactly.
Reopening a lead that is not lost is a tracker 409, which must map to a non-retryable
STATE_CONFLICT.
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
_IDEMPOTENCY_KEY = "33333333-3333-4333-8333-333333333333"


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


def _lost_artifact(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "contactId": _CONTACT_ID,
        "reasonCode": "price",
        "idempotencyKey": _IDEMPOTENCY_KEY,
        "confirmationId": _CONFIRMATION_ID,
    }
    value.update(overrides)
    return json.dumps({k: v for k, v in value.items() if v is not None}).encode()


def _reopen_artifact(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "contactId": _CONTACT_ID,
        "idempotencyKey": _IDEMPOTENCY_KEY,
        "confirmationId": _CONFIRMATION_ID,
    }
    value.update(overrides)
    return json.dumps({k: v for k, v in value.items() if v is not None}).encode()


def _submit(
    provider: EomFunnelProvider, capability_id: str, media_type: str, payload: bytes
) -> tuple[int, dict]:
    request = {
        "protocol_version": 2,
        "job_id": str(uuid4()),
        "capability": {"id": capability_id, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": str(uuid4()),
                "media_type": media_type,
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "display_name": "disposition.json",
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


def _lost(provider: EomFunnelProvider, payload: bytes) -> tuple[int, dict]:
    return _submit(
        provider,
        capabilities.LEAD_LOST_CAPABILITY_ID,
        capabilities.LEAD_LOST_INPUT_MEDIA_TYPE,
        payload,
    )


def _reopen(provider: EomFunnelProvider, payload: bytes) -> tuple[int, dict]:
    return _submit(
        provider,
        capabilities.LEAD_REOPEN_CAPABILITY_ID,
        capabilities.LEAD_REOPEN_INPUT_MEDIA_TYPE,
        payload,
    )


def _receipt(status: dict) -> tuple[str, dict]:
    output = status["result"]["outputs"][0]
    return output["media_type"], json.loads(base64.b64decode(output["payload_base64"]))


def test_lost_mints_challenge_and_relays_bound_fields(wired):
    tracker, provider = wired
    code, status = _lost(provider, _lost_artifact(note="went with a cheaper quote"))
    assert code == 200, status
    assert status["status"] == "completed", status
    media_type, receipt = _receipt(status)
    assert media_type == capabilities.LEAD_LOST_RECEIPT_MEDIA_TYPE
    assert receipt == {"success": True, "lead": {"contact_id": _CONTACT_ID, "lead_stage": "lost"}}
    assert len(tracker.state.minted_challenges) == 1
    sent = tracker.state.disposition_requests[-1]
    assert sent["kind"] == "lost"
    assert sent["contactId"] == _CONTACT_ID
    assert sent["body"] == {
        "challengeId": tracker.state.minted_challenges[-1],
        "confirmationId": _CONFIRMATION_ID,
        "reasonCode": "price",
        "idempotencyKey": _IDEMPOTENCY_KEY,
        "note": "went with a cheaper quote",
    }
    assert tracker.state.proof_requests[-1]["path"].endswith(f"/leads/{_CONTACT_ID}/lost")


def test_lost_without_note_omits_it(wired):
    tracker, provider = wired
    code, status = _lost(provider, _lost_artifact())
    assert code == 200, status
    assert status["status"] == "completed", status
    assert "note" not in tracker.state.disposition_requests[-1]["body"]


def test_reopen_mints_challenge_and_relays_bound_fields(wired):
    tracker, provider = wired
    code, status = _reopen(provider, _reopen_artifact())
    assert code == 200, status
    assert status["status"] == "completed", status
    media_type, receipt = _receipt(status)
    assert media_type == capabilities.LEAD_REOPEN_RECEIPT_MEDIA_TYPE
    assert receipt["lead"]["lead_stage"] == "new"
    sent = tracker.state.disposition_requests[-1]
    assert sent["kind"] == "reopen"
    assert sent["body"] == {
        "challengeId": tracker.state.minted_challenges[-1],
        "confirmationId": _CONFIRMATION_ID,
        "idempotencyKey": _IDEMPOTENCY_KEY,
    }
    assert tracker.state.proof_requests[-1]["path"].endswith(f"/leads/{_CONTACT_ID}/reopen")


def test_reopen_of_a_lead_that_is_not_lost_maps_to_state_conflict(wired):
    tracker, provider = wired
    tracker.set_reopen_status(409, {"detail": "lead is not lost"})
    code, status = _reopen(provider, _reopen_artifact())
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "STATE_CONFLICT"
    assert status["error"]["retryable"] is False


def test_lost_auth_error_maps_to_device_unauthorized(wired):
    tracker, provider = wired
    tracker.set_lost_status(403, {"detail": "confirmation does not match"})
    code, status = _lost(provider, _lost_artifact())
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "DEVICE_UNAUTHORIZED"
    assert status["error"]["retryable"] is False


@pytest.mark.parametrize(
    "payload",
    [
        _lost_artifact(reasonCode="not_a_reason"),
        _lost_artifact(contactId="../evil"),
        _lost_artifact(idempotencyKey=None),
        _lost_artifact(idempotencyKey="not-a-uuid"),
        _lost_artifact(note="x" * 1001),
        _lost_artifact(unexpected="field"),
    ],
    ids=[
        "unknown-reason",
        "non-uuid-contact",
        "missing-key",
        "non-uuid-key",
        "note-too-long",
        "extra-field",
    ],
)
def test_bad_lost_artifact_is_rejected_before_any_tracker_call(wired, payload):
    tracker, provider = wired
    code, body = _lost(provider, payload)
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []
    assert tracker.state.disposition_requests == []


@pytest.mark.parametrize(
    "payload",
    [
        _reopen_artifact(contactId="../evil"),
        _reopen_artifact(idempotencyKey=None),
        _reopen_artifact(reasonCode="spam"),
    ],
    ids=["non-uuid-contact", "missing-key", "reason-not-allowed"],
)
def test_bad_reopen_artifact_is_rejected_before_any_tracker_call(wired, payload):
    tracker, provider = wired
    code, body = _reopen(provider, payload)
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []
    assert tracker.state.disposition_requests == []
