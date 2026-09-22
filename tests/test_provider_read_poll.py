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

_QUEUE = {
    "success": True,
    "leads": [{"contactId": "c1"}],
    "workingLeads": [],
    "pendingHandoffs": [],
    "capabilities": ["lead.customer_handoff"],
}


@pytest.fixture
def wired(tmp_path):
    """A stub tracker with one enrolled device, and a provider wired to it."""
    tracker = StubTracker.start()
    private_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    tracker.register_public_key(
        device_id, private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    tracker.set_queue(dict(_QUEUE))
    credential = store.DeviceCredential(device_id=device_id, private_key=private_key)
    client = TrackerClient(tracker.base_url, credential)
    provider = EomFunnelProvider.start(
        tmp_path / "runtime",
        lambda limit, cursor: client.get_funnel_leads(limit=limit, cursor=cursor),
    )
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
            b"Content-Type: application/json\r\n\r\n",
            artifact_bytes + b"\r\n",
            b"--" + b + b"--\r\n",
        ]
    )
    return f"multipart/form-data; boundary={boundary}", body


def _job_request(job_id: str, artifact: bytes, artifact_id: str) -> bytes:
    request = {
        "protocol_version": 2,
        "job_id": job_id,
        "capability": {"id": capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": artifact_id,
                "media_type": "application/json",
                "byte_size": len(artifact),
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "display_name": "query.json",
                "source_app_id": "connect-automate",
            }
        ],
        "parameters": {},
    }
    return json.dumps(request).encode()


def _submit(
    provider: EomFunnelProvider,
    artifact: bytes,
    *,
    job_id: str,
    artifact_id: str | None = None,
) -> tuple[int, dict]:
    # A real retry re-sends the identical request, so a caller replaying a job
    # passes the same artifact_id it used the first time.
    content_type, body = _multipart(
        _job_request(job_id, artifact, artifact_id or str(uuid4())), artifact
    )
    request = urllib.request.Request(
        url=f"{provider.base_url}v2/jobs", method="POST", data=body
    )
    request.add_header("Authorization", f"Bearer {provider.token}")
    request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _get_json(url: str, token: str) -> tuple[int, dict]:
    request = urllib.request.Request(url=url, method="GET")
    request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _output_json(status: dict) -> dict:
    output = status["result"]["outputs"][0]
    assert output["media_type"] == capabilities.REVIEW_QUEUE_MEDIA_TYPE
    return json.loads(base64.b64decode(output["payload_base64"]))


def test_manifest_is_discoverable(wired):
    _tracker, provider = wired
    code, manifest = _get_json(f"{provider.base_url}v2/manifest", provider.token)
    assert code == 200
    assert manifest["app"]["id"] == "eom-funnel-provider"
    ids = {c["id"] for c in manifest["capabilities"]}
    assert ids == {capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID}
    # The registration file exists and is bearer-protected.
    reg = json.loads(provider.registration_path.read_text())
    assert reg["app_id"] == "eom-funnel-provider"
    assert reg["transport"]["kind"] == "http-loopback-v2"


def test_read_completes_and_returns_the_tracker_queue(wired):
    tracker, provider = wired
    code, status = _submit(provider, b'{"limit":25}', job_id=str(uuid4()))
    assert code == 200, status
    assert status["status"] == "completed"
    assert _output_json(status) == _QUEUE
    # The device proof reached the tracker with the signed query.
    assert tracker.state.proof_requests[-1]["query"] == "limit=25"


def test_replay_is_cached_and_does_not_recall_tracker(wired):
    tracker, provider = wired
    job_id = str(uuid4())
    artifact_id = str(uuid4())
    _submit(provider, b'{"limit":10}', job_id=job_id, artifact_id=artifact_id)
    calls_after_first = len(tracker.state.proof_requests)
    code, status = _submit(provider, b'{"limit":10}', job_id=job_id, artifact_id=artifact_id)
    assert code == 200
    assert status["status"] == "completed"
    # Cached: no second tracker call for the same job.
    assert len(tracker.state.proof_requests) == calls_after_first


def test_reused_job_id_with_other_input_conflicts(wired):
    _tracker, provider = wired
    job_id = str(uuid4())
    first_code, _ = _submit(provider, b'{"limit":10}', job_id=job_id)
    assert first_code == 200
    code, body = _submit(provider, b'{"limit":11}', job_id=job_id)
    assert code == 409, body
    assert body["error"]["code"] == "JOB_CONFLICT"


def test_tracker_auth_error_maps_to_failed_unauthorized(wired):
    tracker, provider = wired
    tracker.force_leads_error(403, {"detail": "operator no longer authorized"})
    code, status = _submit(provider, b"{}", job_id=str(uuid4()))
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "DEVICE_UNAUTHORIZED"
    assert status["error"]["retryable"] is False


def test_retryable_tracker_error_is_not_cached_and_reattempts(wired):
    tracker, provider = wired
    tracker.force_leads_error(503, {"detail": "temporarily unavailable"})
    job_id = str(uuid4())
    artifact_id = str(uuid4())
    code, status = _submit(provider, b"{}", job_id=job_id, artifact_id=artifact_id)
    assert code == 200
    assert status["status"] == "failed"
    assert status["error"]["code"] == "TRACKER_UNAVAILABLE"
    assert status["error"]["retryable"] is True

    # Clear the fault; a re-POST of the SAME job id re-attempts (not cached) and
    # now completes.
    tracker.force_leads_error(200)
    code, status = _submit(provider, b"{}", job_id=job_id, artifact_id=artifact_id)
    assert code == 200
    assert status["status"] == "completed"
    assert _output_json(status) == _QUEUE


def test_bad_capability_version_is_rejected(wired):
    _tracker, provider = wired
    artifact = b"{}"
    request = {
        "protocol_version": 2,
        "job_id": str(uuid4()),
        "capability": {"id": capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID, "version": "9.9"},
        "inputs": [
            {
                "artifact_id": str(uuid4()),
                "media_type": "application/json",
                "byte_size": len(artifact),
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "display_name": "q.json",
                "source_app_id": "connect-automate",
            }
        ],
        "parameters": {},
    }
    content_type, body = _multipart(json.dumps(request).encode(), artifact)
    req = urllib.request.Request(url=f"{provider.base_url}v2/jobs", method="POST", data=body)
    req.add_header("Authorization", f"Bearer {provider.token}")
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            code, payload = response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        code, payload = error.code, json.loads(error.read())
    assert code == 400
    assert payload["error"]["code"] == "INVALID_REQUEST"
