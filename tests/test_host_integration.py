"""Acceptance: the Automate host discovers and invokes this provider end to end.

This is the slice's headline path -- host ``connect.invoke`` over loopback ->
local provider -> device-signed tracker read -> receipt back -- exercised through
the real host Connect v2 client, not the raw protocol. Skipped when the host
package is not importable (it is a dev/test dependency, not a runtime one).
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from stub_tracker import StubTracker

from eom_connect_provider import capabilities, store
from eom_connect_provider.provider import EomFunnelProvider
from eom_connect_provider.tracker_client import TrackerClient

connect = pytest.importorskip("connect_automate.connect")

_QUEUE = {"success": True, "leads": [{"contactId": "c1"}], "workingLeads": []}


@pytest.fixture(autouse=True)
def _active_entitlement(monkeypatch):
    monkeypatch.setattr(
        connect.entitlement,
        "connect_entitlement_decision",
        lambda: connect.entitlement.EntitlementDecision.ACTIVE,
    )


def test_host_discovers_and_invokes_review_queue(tmp_path):
    tracker = StubTracker.start()
    private_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    tracker.register_public_key(
        device_id, private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    tracker.set_queue(dict(_QUEUE))
    client = TrackerClient(tracker.base_url, store.DeviceCredential(device_id, private_key))

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    provider = EomFunnelProvider.start(
        runtime_dir,
        lambda limit, cursor: client.get_funnel_leads(limit=limit, cursor=cursor),
    )
    try:
        catalog = connect.discover_capabilities(runtime_dir)
        items = {
            item.capability_id: item
            for item in catalog.items
            if item.app_id == capabilities.APP_ID
        }
        assert set(items) == {capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID}

        capability = items[capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID]
        content = b'{"limit":25}'
        job = connect.prepare_capability_job(
            capability, content, "application/json", "query.json"
        )
        completed = connect.ConnectV2Client(capability).submit(job, content)
        assert completed.status == "completed"
        assert completed.result is not None
        output = completed.result.outputs[0]
        assert output.media_type == capabilities.REVIEW_QUEUE_MEDIA_TYPE
        assert json.loads(output.payload) == _QUEUE

        # Idempotent replay through the host returns the same result.
        replayed = connect.ConnectV2Client(capability).submit(job, content)
        assert replayed.result == completed.result
    finally:
        provider.stop()
        tracker.stop()

    # Once stopped, the provider is no longer discoverable.
    assert all(
        item.app_id != capabilities.APP_ID
        for item in connect.discover_capabilities(runtime_dir).items
    )
