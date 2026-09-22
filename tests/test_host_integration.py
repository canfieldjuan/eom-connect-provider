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
    provider = EomFunnelProvider.start(runtime_dir, client)
    try:
        catalog = connect.discover_capabilities(runtime_dir)
        items = {
            item.capability_id: item
            for item in catalog.items
            if item.app_id == capabilities.APP_ID
        }
        assert set(items) == set(capabilities.REGISTRY)

        capability = items[capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID]
        # Canonical read: empty artifact, limit/cursor in job parameters.
        content = b""
        job = connect.prepare_capability_job(
            capability, content, "application/json", "query.json", parameters={"limit": 25}
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


_DRAFT_ID = "11111111-1111-4111-8111-111111111111"
_CONFIRMATION_ID = "22222222-2222-4222-8222-222222222222"


def test_host_invokes_approve_send_only_with_confirmation(tmp_path):
    tracker = StubTracker.start()
    private_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    tracker.register_public_key(
        device_id, private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    client = TrackerClient(tracker.base_url, store.DeviceCredential(device_id, private_key))

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    provider = EomFunnelProvider.start(runtime_dir, client)
    try:
        catalog = connect.discover_capabilities(runtime_dir)
        items = {
            item.capability_id: item
            for item in catalog.items
            if item.app_id == capabilities.APP_ID
        }
        capability = items[capabilities.APPROVE_SEND_CAPABILITY_ID]
        assert capability.confirmation_required is True

        approval = json.dumps(
            {"draftId": _DRAFT_ID, "confirmationId": _CONFIRMATION_ID}
        ).encode()
        media_type = capabilities.APPROVE_SEND_INPUT_MEDIA_TYPE

        # The host refuses to prepare a confirmation-required job without confirmation.
        with pytest.raises(connect.ConnectError):
            connect.prepare_capability_job(capability, approval, media_type, "approval.json")

        job = connect.prepare_capability_job(
            capability, approval, media_type, "approval.json", confirmed=True
        )
        completed = connect.ConnectV2Client(capability).submit(job, approval)
        assert completed.status == "completed"
        assert completed.result is not None
        output = completed.result.outputs[0]
        assert output.media_type == capabilities.APPROVE_SEND_RECEIPT_MEDIA_TYPE
        receipt = json.loads(output.payload)
        assert receipt["draftId"] == _DRAFT_ID
        assert receipt["status"] == "sent"
        # The tracker received exactly one minted challenge, carried into the send.
        assert len(tracker.state.minted_challenges) == 1
        assert tracker.state.approve_send_requests[-1]["confirmationId"] == _CONFIRMATION_ID
    finally:
        provider.stop()
        tracker.stop()


def test_host_invokes_estimate_booking_with_confirmation(tmp_path):
    tracker = StubTracker.start()
    private_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    tracker.register_public_key(
        device_id, private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    client = TrackerClient(tracker.base_url, store.DeviceCredential(device_id, private_key))

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    provider = EomFunnelProvider.start(runtime_dir, client)
    try:
        catalog = connect.discover_capabilities(runtime_dir)
        items = {
            item.capability_id: item
            for item in catalog.items
            if item.app_id == capabilities.APP_ID
        }
        capability = items[capabilities.ESTIMATE_BOOKING_CAPABILITY_ID]
        assert capability.confirmation_required is True

        booking = json.dumps(
            {
                "contactId": _DRAFT_ID,
                "scheduledStart": "2026-02-01T09:00:00Z",
                "scheduledEnd": "2026-02-01T10:00:00Z",
                "idempotencyKey": _CONFIRMATION_ID,
                "confirmationId": _CONFIRMATION_ID,
            }
        ).encode()
        media_type = capabilities.ESTIMATE_BOOKING_INPUT_MEDIA_TYPE

        with pytest.raises(connect.ConnectError):
            connect.prepare_capability_job(capability, booking, media_type, "booking.json")

        job = connect.prepare_capability_job(
            capability, booking, media_type, "booking.json", confirmed=True
        )
        completed = connect.ConnectV2Client(capability).submit(job, booking)
        assert completed.status == "completed"
        assert completed.result is not None
        output = completed.result.outputs[0]
        assert output.media_type == capabilities.ESTIMATE_BOOKING_RECEIPT_MEDIA_TYPE
        receipt = json.loads(output.payload)
        assert receipt["contactId"] == _DRAFT_ID
        assert receipt["status"] == "estimate_booked"
        assert len(tracker.state.minted_challenges) == 1
    finally:
        provider.stop()
        tracker.stop()


def test_host_invokes_customer_handoff_with_confirmation(tmp_path):
    tracker = StubTracker.start()
    private_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    tracker.register_public_key(
        device_id, private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    client = TrackerClient(tracker.base_url, store.DeviceCredential(device_id, private_key))

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    provider = EomFunnelProvider.start(runtime_dir, client)
    try:
        catalog = connect.discover_capabilities(runtime_dir)
        items = {
            item.capability_id: item
            for item in catalog.items
            if item.app_id == capabilities.APP_ID
        }
        capability = items[capabilities.CUSTOMER_HANDOFF_CAPABILITY_ID]
        assert capability.confirmation_required is True

        handoff = json.dumps(
            {
                "confirmationId": _CONFIRMATION_ID,
                "handoff": {
                    "atlasContactId": _DRAFT_ID,
                    "idempotencyKey": _CONFIRMATION_ID,
                    "primarySite": {"label": "Main site"},
                },
            }
        ).encode()
        media_type = capabilities.CUSTOMER_HANDOFF_INPUT_MEDIA_TYPE

        with pytest.raises(connect.ConnectError):
            connect.prepare_capability_job(capability, handoff, media_type, "handoff.json")

        job = connect.prepare_capability_job(
            capability, handoff, media_type, "handoff.json", confirmed=True
        )
        completed = connect.ConnectV2Client(capability).submit(job, handoff)
        assert completed.status == "completed"
        assert completed.result is not None
        output = completed.result.outputs[0]
        assert output.media_type == capabilities.CUSTOMER_HANDOFF_RECEIPT_MEDIA_TYPE
        receipt = json.loads(output.payload)
        assert receipt["success"] is True
        assert receipt["handoff"]["atlasContactId"] == _DRAFT_ID
        assert len(tracker.state.minted_challenges) == 1
    finally:
        provider.stop()
        tracker.stop()
