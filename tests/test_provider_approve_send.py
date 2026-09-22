"""Money path: onboarding.draft.approve-send end to end through a proof-verifying stub.

Exercises the provider's money seam -- mint a single-use device challenge, then make
the device-signed approve-send POST -- and its Connect error mapping, without a live
tracker. The stub verifies the same Ed25519 device proof the real tracker does.
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
    """A stub tracker with one enrolled device, and a provider wired to it."""
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
    body = b"".join(
        [
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="request"\r\n',
            b"Content-Type: application/json\r\n\r\n",
            request_bytes + b"\r\n",
            b"--" + b + b"\r\n",
            b'Content-Disposition: form-data; name="artifact"\r\n',
            b"Content-Type: " + capabilities.APPROVE_SEND_INPUT_MEDIA_TYPE.encode() + b"\r\n\r\n",
            artifact_bytes + b"\r\n",
            b"--" + b + b"--\r\n",
        ]
    )
    return f"multipart/form-data; boundary={boundary}", body


def _approval_artifact(draft_id: str = _DRAFT_ID, confirmation_id: str = _CONFIRMATION_ID) -> bytes:
    return json.dumps({"draftId": draft_id, "confirmationId": confirmation_id}).encode()


def _job_request(job_id: str, artifact: bytes, artifact_id: str, parameters: dict) -> bytes:
    request = {
        "protocol_version": 2,
        "job_id": job_id,
        "capability": {"id": capabilities.APPROVE_SEND_CAPABILITY_ID, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": artifact_id,
                "media_type": capabilities.APPROVE_SEND_INPUT_MEDIA_TYPE,
                "byte_size": len(artifact),
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "display_name": "approval.json",
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
    payload = _approval_artifact() if artifact is None else artifact
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
    assert output["media_type"] == capabilities.APPROVE_SEND_RECEIPT_MEDIA_TYPE
    return json.loads(base64.b64decode(output["payload_base64"]))


def test_manifest_advertises_approve_send(wired):
    _tracker, provider = wired
    request = urllib.request.Request(url=f"{provider.base_url}v2/manifest", method="GET")
    request.add_header("Authorization", f"Bearer {provider.token}")
    with urllib.request.urlopen(request, timeout=10) as response:
        manifest = json.loads(response.read())
    caps = {c["id"]: c for c in manifest["capabilities"]}
    assert capabilities.APPROVE_SEND_CAPABILITY_ID in caps
    assert caps[capabilities.APPROVE_SEND_CAPABILITY_ID]["effects"] == {
        "external": True,
        "confirmation_required": True,
    }


def test_approve_send_mints_challenge_and_relays_receipt(wired):
    tracker, provider = wired
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200, status
    assert status["status"] == "completed"
    assert _output_json(status) == {
        "success": True,
        "draftId": _DRAFT_ID,
        "status": "sent",
        "sentAt": "2026-01-01T00:00:00Z",
        "idempotent": False,
    }
    # Exactly one challenge minted, and the value the tracker received is that challenge.
    assert len(tracker.state.minted_challenges) == 1
    sent = tracker.state.approve_send_requests[-1]
    assert sent["draftId"] == _DRAFT_ID
    assert sent["confirmationId"] == _CONFIRMATION_ID
    assert sent["challengeId"] == tracker.state.minted_challenges[-1]
    # The money POST was device-proof-signed at the draft's exact path.
    assert tracker.state.proof_requests[-1]["method"] == "POST"
    assert tracker.state.proof_requests[-1]["path"].endswith(f"/{_DRAFT_ID}/approve-send")


def test_bad_artifact_is_rejected_before_any_tracker_call(wired):
    tracker, provider = wired
    # Missing confirmationId -> malformed request -> 400, before minting a challenge.
    incomplete = json.dumps({"draftId": _DRAFT_ID}).encode()
    code, body = _submit(provider, job_id=str(uuid4()), artifact=incomplete)
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []
    assert tracker.state.approve_send_requests == []


def test_non_uuid_draft_id_is_rejected(wired):
    tracker, provider = wired
    # A draftId that is not a uuid would inject into the tracker URL path -> 400.
    code, body = _submit(
        provider,
        job_id=str(uuid4()),
        artifact=_approval_artifact(draft_id="../evil", confirmation_id=_CONFIRMATION_ID),
    )
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert tracker.state.minted_challenges == []


def test_parameters_are_rejected(wired):
    _tracker, provider = wired
    # A confirmation money path declares no parameters; any is a malformed request.
    code, body = _submit(provider, job_id=str(uuid4()), parameters={"limit": 5})
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"


def test_auth_error_maps_to_device_unauthorized(wired):
    tracker, provider = wired
    tracker.set_approve_send_error(403, {"detail": "operator no longer approver"})
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "DEVICE_UNAUTHORIZED"
    assert status["error"]["retryable"] is False


def test_capability_unavailable_maps_non_retryable(wired):
    tracker, provider = wired
    tracker.set_approve_send_error(501, {"success": False, "error": "atlas_capability_unavailable"})
    code, status = _submit(provider, job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "CAPABILITY_UNAVAILABLE"
    assert status["error"]["retryable"] is False


def test_retryable_failure_is_not_cached_and_reattempts(wired):
    tracker, provider = wired
    tracker.set_approve_send_error(503, {"detail": "temporarily unavailable"})
    job_id = str(uuid4())
    artifact_id = str(uuid4())
    code, status = _submit(provider, job_id=job_id, artifact_id=artifact_id)
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "TRACKER_UNAVAILABLE"
    assert status["error"]["retryable"] is True

    # Clear the fault; a re-POST of the SAME job re-attempts (not cached) and now
    # completes, minting a fresh challenge for the fresh attempt.
    tracker.set_approve_send_error(201)
    code, status = _submit(provider, job_id=job_id, artifact_id=artifact_id)
    assert code == 200, status
    assert status["status"] == "completed"
    assert len(tracker.state.minted_challenges) == 2


def test_completed_replay_is_cached_and_does_not_recall_tracker(wired):
    tracker, provider = wired
    job_id = str(uuid4())
    artifact_id = str(uuid4())
    _submit(provider, job_id=job_id, artifact_id=artifact_id)
    challenges_after_first = len(tracker.state.minted_challenges)
    sends_after_first = len(tracker.state.approve_send_requests)
    code, status = _submit(provider, job_id=job_id, artifact_id=artifact_id)
    assert code == 200
    assert status["status"] == "completed"
    # Idempotent replay: no second challenge, no second send.
    assert len(tracker.state.minted_challenges) == challenges_after_first
    assert len(tracker.state.approve_send_requests) == sends_after_first


def test_reused_job_id_with_other_input_conflicts(wired):
    _tracker, provider = wired
    job_id = str(uuid4())
    artifact_id = str(uuid4())
    first_code, _ = _submit(provider, job_id=job_id, artifact_id=artifact_id)
    assert first_code == 200
    # Same job id, a different draft -> different request identity -> conflict.
    other = _approval_artifact(draft_id="33333333-3333-4333-8333-333333333333")
    code, body = _submit(provider, job_id=job_id, artifact=other, artifact_id=artifact_id)
    assert code == 409, body
    assert body["error"]["code"] == "JOB_CONFLICT"
