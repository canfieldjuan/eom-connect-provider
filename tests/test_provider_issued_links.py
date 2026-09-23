"""Read: onboarding.public-link.list end to end through a proof-verifying stub.

The second read capability, proving the generalized read dispatch routes each read to
its own tracker endpoint. The shared read-seam behaviors (idempotent cache, job
conflict, auth and retryable error mapping) are covered by test_provider_read_poll.py;
this exercises the issued-links dispatch, its output media type, and parameter
passthrough.
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

_PAGE = {
    "success": True,
    "links": [
        {
            "draftId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "contactId": "11111111-1111-4111-8111-111111111111",
            "fullName": "Issued Customer",
            "recipientEmail": "issued@example.test",
            "status": "issued",
            "issuedAt": "2026-08-19T12:00:00Z",
        }
    ],
    "limit": 25,
    "cursor": None,
    "hasMore": False,
    "nextCursor": None,
}

_EMPTY_ARTIFACT = b""


@pytest.fixture
def wired(tmp_path):
    tracker = StubTracker.start()
    private_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    tracker.register_public_key(
        device_id, private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    tracker.set_issued_links(dict(_PAGE))
    client = TrackerClient(
        tracker.base_url, store.DeviceCredential(device_id=device_id, private_key=private_key)
    )
    provider = EomFunnelProvider.start(tmp_path / "runtime", client)
    try:
        yield tracker, provider
    finally:
        provider.stop()
        tracker.stop()


def _multipart(request_bytes: bytes) -> tuple[str, bytes]:
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
            _EMPTY_ARTIFACT + b"\r\n",
            b"--" + b + b"--\r\n",
        ]
    )
    return f"multipart/form-data; boundary={boundary}", body


def _submit(provider: EomFunnelProvider, *, parameters: dict) -> tuple[int, dict]:
    request = {
        "protocol_version": 2,
        "job_id": str(uuid4()),
        "capability": {"id": capabilities.PUBLIC_LINK_LIST_CAPABILITY_ID, "version": "1.0"},
        "inputs": [
            {
                "artifact_id": str(uuid4()),
                "media_type": "application/json",
                "byte_size": 0,
                "sha256": hashlib.sha256(_EMPTY_ARTIFACT).hexdigest(),
                "display_name": "query.json",
                "source_app_id": "connect-automate",
            }
        ],
        "parameters": parameters,
    }
    content_type, body = _multipart(json.dumps(request).encode())
    http = urllib.request.Request(url=f"{provider.base_url}v2/jobs", method="POST", data=body)
    http.add_header("Authorization", f"Bearer {provider.token}")
    http.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(http, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_issued_links_read_completes_and_returns_the_page(wired):
    tracker, provider = wired
    code, status = _submit(provider, parameters={"limit": 25})
    assert code == 200, status
    assert status["status"] == "completed"
    output = status["result"]["outputs"][0]
    assert output["media_type"] == capabilities.PUBLIC_LINK_LIST_MEDIA_TYPE
    assert json.loads(base64.b64decode(output["payload_base64"])) == _PAGE
    # The limit parameter reached the tracker as the signed query, at the right path.
    assert tracker.state.proof_requests[-1]["query"] == "limit=25"
    assert tracker.state.proof_requests[-1]["path"].endswith("/public-onboarding/issued-links")


def test_bad_parameter_is_rejected(wired):
    _tracker, provider = wired
    code, body = _submit(provider, parameters={"limit": 0})
    assert code == 400, body
    assert body["error"]["code"] == "INVALID_REQUEST"
